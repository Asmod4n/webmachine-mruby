#include "webmachine.hpp"
#include "ring_setup.hpp"

#include <sys/stat.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

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
        ::close(docroot_fd_);
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
} // namespace webmachine
