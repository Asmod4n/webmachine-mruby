#include "webmachine.hpp"
#include "ring_setup.hpp"

#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

namespace webmachine
{
namespace
{
// One process, one docroot: the fd RESOLVE_BENEATH anchors against has to
// outlive every request, and a second one would be a second answer to
// "beneath what".
std::string docroot_path_;
int docroot_fd_ = -1;
struct open_how docroot_open_how_ {
};
} // namespace

// The canonical path and the dirfd, once, before the first accept. Canonical
// matters: a relative or symlink-carrying docroot would make "beneath" mean
// whatever the cwd or the link says today, and the confinement is only worth
// as much as the thing it is anchored to.
void docroot_open(mrb_state *mrb, const char *path)
{
    char canonical[PATH_MAX];
    if (::realpath(path, canonical) == nullptr) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "docroot %s: %s", path, std::strerror(errno));
    }
    struct stat info {
    };
    if (::stat(canonical, &info) != 0) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "docroot %s: %s", canonical, std::strerror(errno));
    }
    if (!S_ISDIR(info.st_mode)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "docroot %s is not a directory", canonical);
    }
    // O_PATH is all a dirfd owes openat2: it names the anchor, it never reads.
    const int opened_fd = ::open(canonical, O_DIRECTORY | O_PATH | O_CLOEXEC);
    if (opened_fd < 0) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "docroot %s: %s", canonical, std::strerror(errno));
    }
    if (docroot_fd_ >= 0)
        close_or_raise(mrb, docroot_path_.c_str(), docroot_fd_);
    docroot_fd_ = opened_fd;
    docroot_path_ = canonical;
    // O_NONBLOCK so a FIFO planted in the docroot answers instead of parking an
    // io-wq worker on a writer that never comes; statx refuses it right after.
    docroot_open_how_.flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
    docroot_open_how_.mode = 0;
    docroot_open_how_.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
}

bool docroot_is_open()
{
    return docroot_fd_ >= 0;
}

int docroot_fd()
{
    return docroot_fd_;
}

const char *docroot_path()
{
    return docroot_path_.c_str();
}

// RFC-free: where a request body spills. Empty means nobody named one,
// and slipstream_tmpfile asks the platform instead - TMPDIR, then /tmp.
std::string spill_dir_;

const char *spill_dir_get()
{
    return spill_dir_.empty() ? nullptr : spill_dir_.c_str();
}

void spill_dir_set(const char *path)
{
    spill_dir_.assign(path == nullptr ? "" : path);
}

// RFC 9110 6.4: the body files open in this process. One thread opens
// and closes them - the reactor's - so a plain count is enough. Only
// close_file gives, and only for a descriptor it closed, so the count
// never goes under zero. A give without a take would wrap it, so every
// upload is refused and the fault shows at the first one.
uint32_t body_file_slots_ = 0;

bool body_file_slot_take()
{
    if (body_file_slots_ >= kBodyFilesMax)
        return false;
    body_file_slots_++;
    return true;
}

void body_file_slot_give()
{
    body_file_slots_--;
}

uint32_t body_file_slots_taken()
{
    return body_file_slots_;
}

const struct open_how *docroot_how()
{
    return &docroot_open_how_;
}

namespace
{
// The same three resolve flags every per-request open carries, with
// O_DIRECTORY instead of the file flags: the listing application asks for
// a directory, and a name that is not one is refused by the kernel rather
// than by a check of ours.
//
// openat2 here, not io_uring_prep_openat2: the ring has no operation that
// reads directory entries, so the read below is an ordinary call either
// way, and one confined open beside it is one seam fewer. The confinement
// is the same - it is the docroot fd and these flags that make it, not
// which interface the open went through.
struct open_how docroot_listing_how()
{
    struct open_how how {
    };
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    how.mode = 0;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    return how;
}

// The path a client wrote, as a name openat2 takes: no leading slash, no
// trailing slash, and the docroot itself is ".". False = this name is one
// this process refuses without asking the kernel, and the answer is nil.
bool docroot_listing_name(const char *path, size_t length, std::string &out_name)
{
    out_name.assign(path, length);
    while (!out_name.empty() && out_name.front() == '/')
        out_name.erase(0, 1);
    while (!out_name.empty() && out_name.back() == '/')
        out_name.pop_back();
    if (out_name.empty()) {
        out_name.assign(".");
        return true;
    }
    if (out_name.find('\0') != std::string::npos)
        return false;
    for (size_t index = 0; index < out_name.size();) {
        const size_t text_end = out_name.find('/', index);
        const std::string_view segment(
            out_name.data() + index,
            (text_end == std::string::npos ? out_name.size() : text_end) - index);
        if (segment.empty() || segment == "." || segment == "..")
            return false;
        if (text_end == std::string::npos)
            break;
        index = text_end + 1;
    }
    return true;
}

// One entry of the list, as the template reads it.
mrb_value docroot_listing_entry(mrb_state *mrb, int dirfd, const std::string &name, bool directory,
                                bool sized)
{
    const mrb_value row = mrb_hash_new_capa(mrb, 4);
    mrb_hash_set(mrb, row, mrb_str_new_lit(mrb, "name"),
                 mrb_str_new(mrb, name.data(), name.size()));
    mrb_hash_set(mrb, row, mrb_str_new_lit(mrb, "directory"), mrb_bool_value(directory));
    struct stat info {
    };
    bool stated = false;
    if (sized) {
        if (::fstatat(dirfd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0) {
            stated = true;
        } else if (errno != ENOENT) {
            // The entry going away between the readdir and this call is a
            // race with whoever owns the tree, and the row then says zero.
            // Every other errno is a refusal.
            raise_errno(mrb, "fstat the listed entry", name.c_str(), errno);
        }
    }
    mrb_hash_set(mrb, row, mrb_str_new_lit(mrb, "size"),
                 mrb_fixnum_value(stated ? static_cast<mrb_int>(info.st_size) : 0));
    mrb_hash_set(mrb, row, mrb_str_new_lit(mrb, "mtime"),
                 mrb_fixnum_value(stated ? static_cast<mrb_int>(info.st_mtime) : 0));
    return row;
}

// Webmachine.docroot_listing(path): what is in one directory under the
// docroot, or nil when the path names no directory there. The listing
// application is the only caller, and this is the only thing it needs
// from the server that it cannot write itself - because the boundary is
// the kernel's, and this is where the docroot fd lives.
//
// The answer is a Hash: "mtime" of the directory itself, "truncated" when
// the walk stopped at kListingMax, and "entries", each with "name",
// "directory", "size" and "mtime".
//
// What never appears in it: a name that begins with a dot, and a symbolic
// link. The first is the shape of .git, .env and .htpasswd, and a list is
// not the place to learn that they are there. The second could never be
// opened - the docroot is walked with RESOLVE_NO_SYMLINKS - so a line for
// it could only ever answer 404.
mrb_value docroot_method_listing(mrb_state *mrb, mrb_value)
{
    const char *path = nullptr;
    mrb_int path_len = 0;
    mrb_get_args(mrb, "s", &path, &path_len);
    if (docroot_fd_ < 0)
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "no docroot is open - name one with --docroot");
    std::string name;
    if (!docroot_listing_name(path, static_cast<size_t>(path_len), name))
        return mrb_nil_value();
    const struct open_how how = docroot_listing_how();
    const int opened =
        static_cast<int>(::syscall(SYS_openat2, docroot_fd_, name.c_str(), &how, sizeof(how)));
    if (opened < 0) {
        // A name that is not there, or is not a directory, is an answer:
        // the caller sends 404. Every other errno is a refusal and says so.
        const int why = errno;
        if (why == ENOENT || why == ENOTDIR)
            return mrb_nil_value();
        raise_errno(mrb, "listing", name.c_str(), why);
    }
    struct stat own {
    };
    if (::fstat(opened, &own) != 0) {
        const int why = errno;
        close_or_raise(mrb, name.c_str(), opened);
        raise_errno(mrb, "fstat the listed directory", name.c_str(), why);
    }
    // fdopendir takes the descriptor it is given and closedir ends it.
    DIR *const dir = ::fdopendir(opened);
    if (dir == nullptr) {
        const int why = errno;
        close_or_raise(mrb, name.c_str(), opened);
        raise_errno(mrb, "fdopendir", name.c_str(), why);
    }
    const mrb_value out = mrb_hash_new_capa(mrb, 3);
    const mrb_value rows = mrb_ary_new(mrb);
    // rows and out were made before this mark, so the restore below keeps
    // them and drops only what one entry made.
    const int arena = mrb_gc_arena_save(mrb);
    bool truncated = false;
    size_t taken = 0;
    // readdir answers null for the end of the directory and for a failure
    // alike, and tells the two apart through errno. So errno is cleared
    // before every call and read after the loop.
    errno = 0;
    for (const struct dirent *entry = ::readdir(dir); entry != nullptr;
         errno = 0, entry = ::readdir(dir)) {
        const std::string_view said(entry->d_name);
        if (said.empty() || said.front() == '.')
            continue;
        if (entry->d_type == DT_LNK)
            continue;
        if (taken >= kListingMax) {
            truncated = true;
            break;
        }
        const std::string one(said);
        bool directory = entry->d_type == DT_DIR;
        if (entry->d_type != DT_DIR && entry->d_type != DT_REG) {
            // DT_UNKNOWN: this filesystem did not say, so ask it. Anything
            // that is neither a directory nor a regular file is not a
            // representation, and the file machine would refuse it anyway.
            struct stat info {
            };
            if (::fstatat(opened, one.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0) {
                // The entry went away between the readdir and this call.
                // That is a race with whoever owns the tree, not a
                // refusal; anything else is.
                if (errno == ENOENT)
                    continue;
                const int why = errno;
                if (::closedir(dir) != 0)
                    die_errno("closedir the listed directory", errno);
                raise_errno(mrb, "fstat the listed entry", one.c_str(), why);
            }
            if (S_ISDIR(info.st_mode))
                directory = true;
            else if (!S_ISREG(info.st_mode))
                continue;
        }
        mrb_ary_push(mrb, rows, docroot_listing_entry(mrb, opened, one, directory, true));
        // The arena holds every String and Hash this loop made. A large
        // directory would grow it without bound, so it goes back per
        // entry; the array is what keeps the rows alive.
        mrb_gc_arena_restore(mrb, arena);
        taken++;
    }
    const int walk_errno = errno;
    // closedir ends the descriptor fdopendir took, so its refusal is the
    // close's and is read like any other.
    const int closed = ::closedir(dir);
    if (walk_errno != 0)
        raise_errno(mrb, "readdir", name.c_str(), walk_errno);
    if (closed != 0)
        raise_errno(mrb, "closedir", name.c_str(), errno);
    mrb_hash_set(mrb, out, mrb_str_new_lit(mrb, "entries"), rows);
    mrb_hash_set(mrb, out, mrb_str_new_lit(mrb, "truncated"), mrb_bool_value(truncated));
    mrb_hash_set(mrb, out, mrb_str_new_lit(mrb, "mtime"),
                 mrb_fixnum_value(static_cast<mrb_int>(own.st_mtime)));
    return out;
}
} // namespace

void docroot_init(mrb_state *mrb, struct RClass *webmachine_module)
{
    mrb_define_module_function_id(mrb, webmachine_module, MRB_SYM(docroot_listing),
                                  docroot_method_listing, MRB_ARGS_REQ(1));
    // One source for the bound: the walk above stops there, and the page
    // the listing application renders says the same number.
    mrb_define_const_id(mrb, webmachine_module, MRB_SYM(LISTING_MAX),
                        mrb_fixnum_value(static_cast<mrb_int>(kListingMax)));
}
} // namespace webmachine
