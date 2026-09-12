#include "http1.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <picohttpparser.h>
#include <slipstream_tmpfile.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

#include <ada.h>

namespace webmachine
{
namespace
{
const ReqView *view_ = nullptr;

const struct mrb_data_type request_type = {"webmachine.request", nullptr};

// RFC 9110 9.3.3: n11's create_path names a new disp_path for this run
// only; request_bind clears it again on the way in and on the way out.
std::string disp_override_;
bool disp_override_set_ = false;

// RFC 9110 6.4: the StringIO request.body answered with, for this run.
// One object per run and not one per call: a resource that reads the
// body in a loop asks for it more than once, and an IO that starts over
// each time is not an IO. request_bind drops it.
//
// It is GC-registered rather than kept in the arena: the memo outlives
// the callback that built it, and every later callback in the same run
// gets the same object back.
mrb_value body_io_ = mrb_nil_value();
// The VM the memo was registered in, so request_bind can unregister it
// without every caller having to hand one over. Set with body_io_ and
// cleared with it.
mrb_state *body_io_mrb_ = nullptr;

// The request being answered. Outside a resource callback there is none,
// and that is a refusal with a name.
const ReqView *request_being_answered(mrb_state *mrb)
{
    if (view_ == nullptr) {
        mrb_raise(mrb, E_RUNTIME_ERROR,
                  "request is only alive inside a resource callback - there is no request "
                  "being answered here");
    }
    return view_;
}

// RFC 9110 9.1: the method, by name.
//: () -> (String | NilClass)
mrb_value req_method(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    switch (v->method) {
        case flow::Method::kGet:
            return mrb_str_new_lit(mrb, "GET");
        case flow::Method::kHead:
            return mrb_str_new_lit(mrb, "HEAD");
        case flow::Method::kPost:
            return mrb_str_new_lit(mrb, "POST");
        case flow::Method::kPut:
            return mrb_str_new_lit(mrb, "PUT");
        case flow::Method::kDelete:
            return mrb_str_new_lit(mrb, "DELETE");
        case flow::Method::kOptions:
            return mrb_str_new_lit(mrb, "OPTIONS");
        case flow::Method::kOther:
            break;
    }
    if (v->method_token != nullptr)
        return mrb_str_new(mrb, v->method_token, v->method_token_len);
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "this request's method is outside the set the flow names, and its bytes are "
              "not lent on this path");
    return mrb_nil_value();
}

// RFC 9110 4.2.1: the request-target as it arrived, query and all.
//: () -> String
mrb_value req_uri(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    return mrb_str_new(mrb, v->request_target, v->request_target_len);
}

// RFC 9110 4.2.1: the target up to '?'.
//: () -> String
mrb_value req_path(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    return mrb_str_new(mrb, v->request_target, v->path_len);
}

// RFC 9110 4.2.1: what is left of the path for the resource to dispatch
// on - n11's create_path override wins when this run set one.
//: () -> String
mrb_value req_disp_path(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    if (disp_override_set_)
        return mrb_str_new(mrb, disp_override_.data(), disp_override_.size());
    // The spans are the matching frame's; a view without a match has none.
    if (v->spans != nullptr && v->spans->has_splat) {
        return mrb_str_new(mrb, v->spans->splat.p, v->spans->splat.n);
    }
    return mrb_str_new(mrb, v->request_target, v->path_len);
}

// RFC 9110 4.2.1: the Symbol tokens this route bound, by name.
//: () -> Hash
mrb_value req_path_info(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    if (v->spans == nullptr)
        return mrb_hash_new(mrb);
    mrb_value h = mrb_hash_new_capa(mrb, v->spans->nbind);
    if (v->table == nullptr || v->route < 0)
        return h;
    for (uint8_t i = 0; i < v->spans->nbind; i++) {
        const mrb_sym k = static_cast<mrb_sym>(v->table->binding_sym(v->route, i));
        if (k == 0)
            continue;
        mrb_hash_set(mrb, h, mrb_symbol_value(k),
                     mrb_str_new(mrb, v->spans->bind[i].p, v->spans->bind[i].n));
    }
    return h;
}

// RFC 9110 4.2.1: the splat's segments, in order.
//: () -> Array
mrb_value req_path_tokens(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    mrb_value a = mrb_ary_new(mrb);
    if (v->spans == nullptr || !v->spans->has_splat)
        return a;
    const char *p = v->spans->splat.p;
    size_t n = v->spans->splat.n;
    size_t at = 0;
    // One String per segment, and a splat takes as many as the client
    // sends. The array is rooted before the save.
    const int ai = mrb_gc_arena_save(mrb);
    while (at < n) {
        size_t seg = at;
        while (at < n && p[at] != '/')
            at++;
        mrb_ary_push(mrb, a, mrb_str_new(mrb, p + seg, at - seg));
        mrb_gc_arena_restore(mrb, ai);
        if (at < n)
            at++;
    }
    return a;
}

// RFC 9110 4.2.1: the raw query, without the '?'.
//: () -> String
mrb_value req_query_string(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    if (v->path_len >= v->request_target_len)
        return mrb_str_new(mrb, "", 0);
    const size_t off = v->path_len + 1;
    return mrb_str_new(mrb, v->request_target + off, v->request_target_len - off);
}

// application/x-www-form-urlencoded, WHATWG URL Standard: the pairs of
// a query string, percent-decoded, '+' read as a space.
//
// Not RFC 9110. That specification defines the http URI scheme, where
// the query is an opaque string, as it is in RFC 3986 3.4. Key-value
// pairs are not an HTTP concept at all; they are the
// form encoding's, and its living definition is the URL Standard. That
// standard splits on '&' (0x26) and nothing else. The ';' this used to
// accept came from a note to CGI authors in HTML 4.01 B.2.2 and was
// removed from the web platform in 2020, so it goes here too. Cookies
// keep their ';' - that one is specified, in RFC 6265 4.2.
//
// ada owns the decoded pairs for the length of the call and hands out
// views into them, so every String below is made while they are alive.
//: () -> Hash
mrb_value req_query(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    mrb_value h = mrb_hash_new(mrb);
    if (v->path_len >= v->request_target_len)
        return h;
    const char *p = v->request_target + v->path_len + 1;
    const size_t n = v->request_target_len - v->path_len - 1;

    ada::url_search_params params{std::string_view(p, n)};
    // Two Strings per pair, and the pair count is the client's to choose:
    // held to the end they would fill a 100-slot MRB_GC_FIXED_ARENA at ~50
    // pairs. The hash is rooted before the save, so it keeps what it was
    // handed and the restore only drops the temporaries.
    const int ai = mrb_gc_arena_save(mrb);
    for (const auto &kv : params) {
        // Frozen key: hash.c h_key_for would otherwise dup it (ea96df2).
        const mrb_value key =
            mrb_obj_freeze(mrb, mrb_str_new(mrb, kv.first.data(), kv.first.size()));
        mrb_hash_set(mrb, h, key, mrb_str_new(mrb, kv.second.data(), kv.second.size()));
        mrb_gc_arena_restore(mrb, ai);
    }
    return h;
}

// RFC 9110 5.1/5.3, RFC 9113 8.2: the head's fields, names lowercased,
// repeats joined with ", ". A request that sent none answers an empty
// Hash. The fields live as long as the request: a parked HTTP/2 stream
// copies them (H2Stream::field_blob), so they are never gone.
//: () -> Hash
mrb_value req_headers(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    const struct phr_header *hs = static_cast<const struct phr_header *>(v->fields);
    mrb_value h = mrb_hash_new_capa(mrb, static_cast<mrb_int>(v->field_count));
    for (size_t i = 0; i < v->field_count; i++) {
        mrb_value name = mrb_str_new(mrb, hs[i].name, hs[i].name_len);
        char *np = RSTRING_PTR(name);
        for (mrb_int j = 0; j < RSTRING_LEN(name); j++) {
            if (np[j] >= 'A' && np[j] <= 'Z')
                np[j] = static_cast<char>(np[j] + 32);
        }
        // hash.c h_key_for dups every String key that is not already
        // frozen; freezing after the downcase hands it the final bytes and
        // skips one allocation and one copy per header (ea96df2).
        name = mrb_obj_freeze(mrb, name);
        const mrb_value had = mrb_hash_get(mrb, h, name);
        if (mrb_string_p(had)) {
            mrb_str_cat_lit(mrb, had, ", ");
            mrb_str_cat(mrb, had, hs[i].value, hs[i].value_len);
            continue;
        }
        mrb_hash_set(mrb, h, name, mrb_str_new(mrb, hs[i].value, hs[i].value_len));
    }
    return h;
}

// RFC 9110 6.4: put this body in the filesystem, under a directory
// named for what is in it.
//
//   def take
//     request.body.save("/var/uploads", "photo.png") { |dir, err| dir }
//   end
//
// The block is told where the content landed, or what stopped it.
// Whatever it answers is the answer's body, spelled with to_s the way
// Ruby spells anything - the same shape as to_html, whose value is the
// body as well. So nothing in the block reaches for the response
// object, and a resource that only wants to say where the file went
// says it in one line. nil and false keep the value to the block, and
// then the resource spells the answer itself.
//
// It answers no status and it cannot: a save that failed is this
// server's fault, so this server spells the 500 and the error log
// names the reason.
//
// It is a block and not a return value for the reason `watch` is one:
// a call site that yields can be resumed later, so when the link and
// the copy move through the ring, no resource has to be rewritten.
// Without a block the path is answered, and a failure raises just the
// same.
//
// This is a method of the object request.body answers and of that
// object only - it is defined on that object's singleton class, so
// File and StringIO are untouched for everyone else.
//
// The application names a directory it chose and the name the user
// gave. Everything between them is the digest of the octets, and that
// is what makes the rest of this safe:
//
//   - Two uploads of the same octets get the same directory, because
//     they are the same file. mkdir is the atomic claim, so there is
//     no window between asking whether a name is free and taking it.
//   - A directory that is already there means this server already
//     holds exactly these octets. Nothing is written and nothing is
//     read: the block is told the directory at once.
//   - The same octets under a second name find that directory and get
//     a second link inside it. One inode, two names, no copy.
//   - Nothing the client sent reaches a path component except the
//     leaf, and the leaf may hold no slash, no "..", and nothing
//     empty.
//
// Where the octets come from. A body that went to a file is linked
// into place: they are already on the disk, written as they arrived,
// so the whole upload ends with one link. A link only works inside one
// filesystem, so when conf.spill_dir and this directory are on
// different ones the kernel copies with copy_file_range and no octet
// passes through this process. A body in memory is written out; it is
// under the in-memory limit by definition.
//
// The digest is taken here rather than while the body arrives. It
// costs one pass over octets that are in the page cache, and only a
// request that saves pays for it - a server that never calls this
// never hashes anything.

// #54: did the resource that is running say this callback may save?
// The fold wrote the answer on the Resource, and response.cpp is what
// knows which resource is live.
bool save_declared(mrb_state *mrb)
{
    return response_saves_body(mrb);
}

// What one save was asked for, and what became of it. `dir` is the
// directory the content lives in once this returns, and `err` is what
// stopped it - exactly one of the two is filled.
struct SaveAsk {
    std::string_view dir;
    std::string_view name;
    std::string out;
    std::string err;
};

// The digest of what arrived, as lowercase hex. False when the body
// cannot be read, which is the caller's error line.
bool body_digest(const ReqView *v, char (&hex)[SHA256_DIGEST_LENGTH * 2 + 1], std::string &err)
{
    unsigned char sum[SHA256_DIGEST_LENGTH];
    if (v->content_fd >= 0) {
        // The EVP form: OpenSSL 3.0 deprecated SHA256_Init and its two
        // companions, and the one-shot SHA256 below is the only low-level
        // call it kept.
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx == nullptr || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            err = "EVP_DigestInit_ex failed";
            return false;
        }
        char buf[64 * 1024];
        off_t at = 0;
        for (;;) {
            const ssize_t got = ::pread(v->content_fd, buf, sizeof(buf), at);
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                EVP_MD_CTX_free(ctx);
                err = std::strerror(errno);
                return false;
            }
            if (got == 0)
                break;
            EVP_DigestUpdate(ctx, buf, static_cast<size_t>(got));
            at += got;
        }
        EVP_DigestFinal_ex(ctx, sum, nullptr);
        EVP_MD_CTX_free(ctx);
    } else {
        SHA256(reinterpret_cast<const unsigned char *>(v->content), v->content_len, sum);
    }
    static const char kHex[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hex[i * 2] = kHex[sum[i] >> 4];
        hex[i * 2 + 1] = kHex[sum[i] & 0x0f];
    }
    hex[SHA256_DIGEST_LENGTH * 2] = 0;
    return true;
}

// Write the octets out, for the two cases a link cannot serve: a body
// that is in memory, and a file on another filesystem. The kernel does
// the copying in the second one - no octet passes through this process.
bool body_copy(const ReqView *v, const std::string &path, std::string &err)
{
    // The name appears when every octet is in the file, and not before.
    // Writing into the final name made a half-written upload the answer
    // to every save after it: the name is there, so access() says the
    // content is held and EEXIST on the open was read as success. A
    // request that overlapped another, or a process that died mid-write,
    // left that short file standing for good. So the octets go into a
    // temporary file beside it, and the name is a link made at the end.
    const size_t slash = path.rfind('/');
    std::string tmp(path, 0, slash == std::string::npos ? 0 : slash + 1);
    tmp.append("wm-save-XXXXXX");
    const int out = ::mkstemp(&tmp[0]);
    if (out < 0) {
        err = tmp + ": " + std::strerror(errno);
        return false;
    }
    bool ok = true;
    if (v->content_fd >= 0) {
        off_t from = 0;
        size_t left = v->content_len;
        while (left != 0) {
            const ssize_t n = ::copy_file_range(v->content_fd, &from, out, nullptr, left, 0);
            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                err = std::strerror(errno);
                ok = false;
                break;
            }
            left -= static_cast<size_t>(n);
        }
    } else {
        const char *p = v->content;
        size_t left = v->content_len;
        while (left != 0) {
            const ssize_t n = ::write(out, p, left);
            if (n <= 0) {
                if (errno == EINTR)
                    continue;
                err = std::strerror(errno);
                ok = false;
                break;
            }
            p += static_cast<size_t>(n);
            left -= static_cast<size_t>(n);
        }
    }
    // The link is the claim, so what it claims has to be on the disk
    // first - a name that outlives the octets is the hole this replaces.
    if (ok && ::fsync(out) != 0) {
        err = std::strerror(errno);
        ok = false;
    }
    ::close(out);
    if (ok) {
        // EEXIST is another request that finished the same octets first.
        // The digest says the two files hold the same content, so the name
        // that stands is as good as this one.
        if (::link(tmp.c_str(), path.c_str()) != 0 && errno != EEXIST) {
            err = path + ": " + std::strerror(errno);
            ok = false;
        }
    }
    ::unlink(tmp.c_str());
    return ok;
}

// One level of the upload tree. An EEXIST is this server's own earlier
// save, and it has to be a directory: a symbolic link in its place sends
// every upload under it to another tree.
bool save_mkdir(const std::string &path, std::string &err)
{
    if (::mkdir(path.c_str(), 0700) == 0)
        return true;
    if (errno != EEXIST) {
        err = path + ": " + std::strerror(errno);
        return false;
    }
    struct stat st;
    if (::lstat(path.c_str(), &st) < 0) {
        err = path + ": " + std::strerror(errno);
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        err = path + ": this name is there already, and it is no directory";
        return false;
    }
    return true;
}

// One save, start to end. Everything it can answer is in the ask.
void save_body(mrb_state *mrb, SaveAsk &ask)
{
    // A NUL ends the path this name becomes, so the file on the disk would
    // carry a shorter name than the one the app asked for.
    if (ask.name.empty() || ask.name.find('/') != std::string_view::npos ||
        ask.name.find('\0') != std::string_view::npos || ask.name == "." || ask.name == "..") {
        ask.err = "the name is one file name, with no directory in it";
        return;
    }
    const ReqView *const v = request_being_answered(mrb);
    if (v->content == nullptr && v->content_fd < 0) {
        ask.err = "this request carried no body";
        return;
    }
    // #54: every stop is declared, and so is this. A callback that did
    // not say `save: true` got its body in memory when it was small, so
    // a save here would be a second write of every octet - the cost the
    // declaration exists to remove. The refusal names the line to write.
    if (!save_declared(mrb)) {
        ask.err = "this callback did not say it saves - write `reads_body :<callback>, save: true`";
        return;
    }
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    if (!body_digest(v, hex, ask.err))
        return;

    // Two octets of the digest make the first level, so one directory
    // never holds every upload this server ever took.
    std::string path(ask.dir);
    while (path.size() > 1 && path.back() == '/')
        path.pop_back();
    path.push_back('/');
    path.append(hex, 2);
    if (!save_mkdir(path, ask.err))
        return;
    path.push_back('/');
    path.append(hex, SHA256_DIGEST_LENGTH * 2);
    if (!save_mkdir(path, ask.err))
        return;
    ask.out = path;
    path.push_back('/');
    path.append(ask.name);

    // Already here, under this very name: nothing to write and nothing
    // to read.
    if (::access(path.c_str(), F_OK) == 0)
        return;

    if (v->content_fd >= 0) {
        const int rc = slipstream_tmpfile_link(v->content_fd, path.c_str());
        if (rc == 0 || rc == -EEXIST)
            return;
        // -ENOENT is a temporary file the mkstemp arm made, which has no
        // name to link from; -EXDEV is another filesystem. Both are a copy.
        if (rc != -ENOENT && rc != -EXDEV && rc != -EOPNOTSUPP) {
            ask.err = std::strerror(-rc);
            return;
        }
    }
    if (!body_copy(v, path, ask.err))
        ask.out.clear();
}

//: (String, String) { (String?, Webmachine::Error?) -> untyped } -> untyped
mrb_value body_save(mrb_state *mrb, mrb_value)
{
    const char *dir = nullptr;
    mrb_int dlen = 0;
    const char *leaf = nullptr;
    mrb_int llen = 0;
    mrb_value blk = mrb_nil_value();
    mrb_get_args(mrb, "ss&", &dir, &dlen, &leaf, &llen, &blk);
    SaveAsk ask;
    ask.dir = {dir, static_cast<size_t>(dlen)};
    ask.name = {leaf, static_cast<size_t>(llen)};
    save_body(mrb, ask);
    if (mrb_nil_p(blk)) {
        if (!ask.err.empty()) {
            mrb_raisef(mrb, E_WM_ERROR(mrb), "request.body.save: %s", ask.err.c_str());
        }
        return mrb_str_new(mrb, ask.out.data(), ask.out.size());
    }
    mrb_value argv[2] = {
        ask.err.empty() ? mrb_str_new(mrb, ask.out.data(), ask.out.size()) : mrb_nil_value(),
        ask.err.empty() ? mrb_nil_value()
                        : mrb_exc_new(mrb, E_WM_ERROR(mrb), ask.err.data(), ask.err.size())};
    const mrb_value said = mrb_yield_argv(mrb, blk, 2, argv);
    // The block has been told. The status is not its business: a save
    // that failed is this server's fault, and this server says 500.
    if (!ask.err.empty()) {
        mrb_raisef(mrb, E_WM_ERROR(mrb), "request.body.save: %s", ask.err.c_str());
    }
    // Whatever the block answers is the answer's body, spelled with to_s
    // the way Ruby spells anything. nil and false are the block keeping
    // its value to itself, and then the resource spells the answer.
    if (mrb_test(said)) {
        const mrb_value text = mrb_obj_as_string(mrb, said);
        response_take_body(mrb, {RSTRING_PTR(text), static_cast<size_t>(RSTRING_LEN(text))});
    }
    return said;
}

// RFC 9110 6.4: the request body, as an IO; nil when none arrived.
//
// An IO and not a String, because a body is not always in memory: over
// conf.max_body's in-memory size it lives in a file, and a resource that
// reads it must not care which. What it can do is what both answer -
// read, gets, getc, each, pos, seek, rewind, size, eof?.
//
// The bytes are copied into the String the StringIO holds. The wire
// buffer they came from is the connection's, and it is refilled by the
// next read; a body that a resource keeps has to be its own.
//: () -> (StringIO | NilClass)
mrb_value req_body(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    if (v->content == nullptr && v->content_fd < 0)
        return mrb_nil_value();
    if (!mrb_nil_p(body_io_))
        return body_io_;

    mrb_value io;
    if (v->content_fd >= 0) {
        // RFC 9110 6.4: a large body is a file, and the resource reads it
        // like any other. The descriptor is duplicated first: the h1
        // connection or the h2 stream owns the one it wrote, and a File that
        // closes with the run must not take it. The copy starts at the first
        // octet, because the write left the owner's offset at the last.
        const int fd = ::dup(v->content_fd);
        if (mrb_unlikely(fd < 0)) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "request.body cannot be opened for reading");
        }
        if (mrb_unlikely(::lseek(fd, 0, SEEK_SET) != 0)) {
            ::close(fd);
            mrb_raise(mrb, E_RUNTIME_ERROR, "request.body cannot be rewound");
        }
        mrb_value argv[2] = {mrb_int_value(mrb, fd), mrb_str_new_lit(mrb, "r")};
        io = mrb_funcall_argv(mrb, mrb_obj_value(mrb_class_get_id(mrb, MRB_SYM(File))),
                              MRB_SYM(for_fd), 2, argv);
    } else {
        struct RClass *const sio = mrb_class_get_id(mrb, MRB_SYM(StringIO));
        const mrb_value bytes = mrb_str_new(mrb, v->content, v->content_len);
        io = mrb_obj_new(mrb, sio, 1, &bytes);
    }
    // The one method this object has that its class does not: see
    // body_save. It is defined on the singleton, so no other File or
    // StringIO in this VM grows a save.
    mrb_define_method_id(mrb, mrb_singleton_class_ptr(mrb, io), MRB_SYM(save), body_save,
                         MRB_ARGS_REQ(2) | MRB_ARGS_BLOCK());
    mrb_gc_register(mrb, io);
    body_io_ = io;
    body_io_mrb_ = mrb;
    return body_io_;
}

// RFC 9110 6.4: is there a body worth reading? An empty body counts as none.
//: () -> (TrueClass | FalseClass)
mrb_value req_has_body(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(request_being_answered(mrb)->content_len > 0);
}

// RFC 9110 5.1: one field, by its (already-lowercase) name; nil when absent.
// RFC 9110 5.1: the value of one of the ten fields Resource#request names,
// or nil when the request did not carry it. Where it sits was noted by the
// one pass over the field array (http::NamedFieldIndex); this reads it.
} // namespace

void join_repeated_fields(const ReqView *v, std::string_view name, std::string_view sep,
                          std::string &out)
{
    out.clear();
    const auto *h = static_cast<const struct phr_header *>(v->fields);
    for (size_t i = 0; i < v->field_count; i++) {
        if (h[i].name_len != name.size())
            continue;
        bool same = true;
        for (size_t k = 0; k < name.size() && same; k++) {
            char c = h[i].name[k];
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c + 32);
            same = c == name[k];
        }
        if (!same)
            continue;
        if (!out.empty())
            out.append(sep);
        out.append(h[i].value, h[i].value_len);
    }
}

namespace
{
mrb_value req_named(mrb_state *mrb, http::NamedField f)
{
    const ReqView *v = request_being_answered(mrb);
    if (v->values == nullptr || !v->values->named.carries(f))
        return mrb_nil_value();
    // The index is applied by the thing that stored it, against the array
    // it is being applied to - see http::NamedFieldIndex. A position this
    // request's array cannot reach reads as "no such field" instead of
    // reading past the end.
    const struct phr_header *h = v->values->named.find(
        f, {static_cast<const struct phr_header *>(v->fields), v->field_count});
    if (h == nullptr)
        return mrb_nil_value();
    return mrb_str_new(mrb, h->value, h->value_len);
}

// RFC 9110 8.3: the entity's media type.
//: () -> (String | NilClass)
mrb_value req_content_type(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kContentType);
}
// RFC 9110 8.6: the entity's length, as webmachine-ruby hands it back -
// a String the caller is expected to .to_i.
//: () -> (String | NilClass)
mrb_value req_content_length(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kContentLength);
}
// RFC 9110 11.6.2: the credentials, verbatim.
//: () -> (String | NilClass)
mrb_value req_authorization(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kAuthorization);
}
// RFC 9110 12.5.1: what the client would rather have.
//: () -> (String | NilClass)
mrb_value req_accept(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kAccept);
}
// RFC 9110 12.5.3: which codings it will take.
//: () -> (String | NilClass)
mrb_value req_accept_encoding(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kAcceptEncoding);
}
// RFC 9110 13.1.1: the precondition on the current representation.
//: () -> (String | NilClass)
mrb_value req_if_match(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kIfMatch);
}
// RFC 9110 13.1.2: its negation.
//: () -> (String | NilClass)
mrb_value req_if_none_match(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    if (v->values != nullptr && v->values->if_none_match_repeats) {
        std::string joined;
        join_repeated_fields(v, "if-none-match", ", ", joined);
        return mrb_str_new(mrb, joined.data(), joined.size());
    }
    return req_named(mrb, http::NamedField::kIfNoneMatch);
}
// RFC 9110 13.1.3: the date form of the same question.
//: () -> (String | NilClass)
mrb_value req_if_modified_since(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kIfModifiedSince);
}
// RFC 9110 13.1.4: and its negation.
//: () -> (String | NilClass)
mrb_value req_if_unmodified_since(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kIfUnmodifiedSince);
}

//: () -> (String | NilClass)
mrb_value req_host(mrb_state *mrb, mrb_value)
{
    return req_named(mrb, http::NamedField::kHost);
}

// RFC 6265 5.4: the Cookie header's k=v pairs, lazily parsed into a
// Hash. No Cookie field: an empty Hash, same as webmachine-ruby.
//: () -> Hash
mrb_value req_cookies(mrb_state *mrb, mrb_value)
{
    const ReqView *v = request_being_answered(mrb);
    mrb_value h = mrb_hash_new(mrb);
    // RFC 6265 4.2: the one pass kept the span; the field array is not
    // walked again to find it.
    if (v->values == nullptr || v->values->cookie == nullptr)
        return h;
    // RFC 6265 5.4 / RFC 9113 8.2.3: several Cookie lines are one cookie
    // string, joined with "; ".
    std::string joined;
    if (v->values->cookie_repeats)
        join_repeated_fields(v, "cookie", "; ", joined);
    const char *p = v->values->cookie_repeats ? joined.data() : v->values->cookie;
    const size_t n = v->values->cookie_repeats ? joined.size() : v->values->cookie_len;
    size_t at = 0;
    // As in req_query: the cookie count is the client's, so each pair's
    // Strings are dropped once the hash holds them.
    const int ai = mrb_gc_arena_save(mrb);
    while (at < n) {
        while (at < n && (p[at] == ' ' || p[at] == '\t'))
            at++;
        const size_t start = at;
        while (at < n && p[at] != ';')
            at++;
        size_t end = at;
        while (end > start && (p[end - 1] == ' ' || p[end - 1] == '\t'))
            end--;
        if (at < n)
            at++; // skip ';'
        if (end <= start)
            continue;
        size_t eq = start;
        while (eq < end && p[eq] != '=')
            eq++;
        if (eq >= end)
            continue;
        // Frozen key: hash.c h_key_for would otherwise dup it (ea96df2).
        mrb_hash_set(mrb, h, mrb_str_new_frozen(mrb, p + start, eq - start),
                     mrb_str_new(mrb, p + eq + 1, end - eq - 1));
        mrb_gc_arena_restore(mrb, ai);
    }
    return h;
}

// RFC 9110 4.2.1: base_uri as webmachine-ruby spells it - scheme and
// Host only, no port/query normalization, no URI object.
//: () -> String
mrb_value req_base_uri(mrb_state *mrb, mrb_value)
{
    const mrb_value host = req_named(mrb, http::NamedField::kHost);
    const ReqView *v = request_being_answered(mrb);
    mrb_value s = v->tls ? mrb_str_new_lit(mrb, "https://") : mrb_str_new_lit(mrb, "http://");
    if (!mrb_nil_p(host)) {
        mrb_str_cat(mrb, s, RSTRING_PTR(host), static_cast<size_t>(RSTRING_LEN(host)));
    }
    mrb_str_cat_lit(mrb, s, "/");
    return s;
}

// RFC 9110 9.3.1: is this a GET?
//: () -> (TrueClass | FalseClass)
mrb_value req_is_get(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(request_being_answered(mrb)->method == flow::Method::kGet);
}
// RFC 9110 9.3.2: is this a HEAD?
//: () -> (TrueClass | FalseClass)
mrb_value req_is_head(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(request_being_answered(mrb)->method == flow::Method::kHead);
}
// RFC 9110 9.3.3: is this a POST?
//: () -> (TrueClass | FalseClass)
mrb_value req_is_post(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(request_being_answered(mrb)->method == flow::Method::kPost);
}
// RFC 9110 9.3.4: is this a PUT?
//: () -> (TrueClass | FalseClass)
mrb_value req_is_put(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(request_being_answered(mrb)->method == flow::Method::kPut);
}
// RFC 9110 9.3.5: is this a DELETE?
//: () -> (TrueClass | FalseClass)
mrb_value req_is_delete(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(request_being_answered(mrb)->method == flow::Method::kDelete);
}
// RFC 9110 9.3.7: is this an OPTIONS?
//: () -> (TrueClass | FalseClass)
mrb_value req_is_options(mrb_state *mrb, mrb_value)
{
    return mrb_bool_value(request_being_answered(mrb)->method == flow::Method::kOptions);
}

// RFC 9110: Resource#request - a fresh handle on every call, never one the
// process keeps and hands back. What the caller does with it afterwards is
// the caller's; the callback's own GC arena roots it, the same way Response
// is rooted.
//: () -> Webmachine::Request
mrb_value resource_request(mrb_state *mrb, mrb_value)
{
    request_being_answered(mrb);
    struct RClass *wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
    struct RClass *rc = mrb_class_get_under_id(mrb, wm, MRB_SYM(Request));
    return mrb_obj_value(mrb_data_object_alloc(mrb, rc, nullptr, &request_type));
}
} // namespace

// RFC 9110: this run's request, or nothing between runs - and any
// create_path override goes with it, because it belongs to the run that is
// ending, never to the next one.
void request_bind(const ReqView *view)
{
    view_ = view;
    disp_override_.clear();
    disp_override_set_ = false;
    if (body_io_mrb_ != nullptr) {
        mrb_gc_unregister(body_io_mrb_, body_io_);
        body_io_ = mrb_nil_value();
        body_io_mrb_ = nullptr;
    }
}

// RFC 9110 9.3.3: n11's create_path names a new disp_path for this run;
// the next request_bind (in or out) clears it again.
void request_disp_override(const char *p, size_t n)
{
    disp_override_.assign(p, n);
    disp_override_set_ = true;
}

// RFC 9110: Webmachine::Request, defined once at gem init.
void request_init(mrb_state *mrb, struct RClass *wm)
{
    struct RClass *req = mrb_define_class_under_id(mrb, wm, MRB_SYM(Request), mrb->object_class);
    MRB_SET_INSTANCE_TT(req, MRB_TT_CDATA);
    mrb_undef_class_method_id(mrb, req, MRB_SYM(new));
    mrb_define_method_id(mrb, req, MRB_SYM(method), req_method, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(uri), req_uri, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(path), req_path, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(disp_path), req_disp_path, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(path_info), req_path_info, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(path_tokens), req_path_tokens, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(query), req_query, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(query_string), req_query_string, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(headers), req_headers, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(body), req_body, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM_Q(has_body), req_has_body, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(content_type), req_content_type, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(content_length), req_content_length, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(authorization), req_authorization, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(accept), req_accept, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(accept_encoding), req_accept_encoding, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(if_match), req_if_match, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(if_none_match), req_if_none_match, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(if_modified_since), req_if_modified_since,
                         MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(if_unmodified_since), req_if_unmodified_since,
                         MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(host), req_host, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(cookies), req_cookies, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM(base_uri), req_base_uri, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM_Q(get), req_is_get, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM_Q(head), req_is_head, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM_Q(post), req_is_post, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM_Q(put), req_is_put, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM_Q(delete), req_is_delete, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, req, MRB_SYM_Q(options), req_is_options, MRB_ARGS_NONE());

    struct RClass *res = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));
    mrb_define_method_id(mrb, res, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
    struct RClass *wsres = mrb_class_get_under_id(mrb, wm, MRB_SYM(WebsocketResource));
    mrb_define_method_id(mrb, wsres, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
    struct RClass *sseres = mrb_class_get_under_id(mrb, wm, MRB_SYM(SseResource));
    mrb_define_method_id(mrb, sseres, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
}

// RFC 9110 5.1: the one way a stored position is read - see the
// declaration in webmachine.hpp for why it is the only one. Lives here
// because this is a file where phr_header is a complete type; the header
// only forward-declares it.
namespace http
{
const struct phr_header *NamedFieldIndex::find(NamedField f, HeaderList hs) const
{
    if (hs.items == nullptr || !carries(f))
        return nullptr;
    const uint8_t i = at[static_cast<uint8_t>(f)];
    // A position this array cannot reach is no field. Every producer
    // builds the index beside the array it came from, so this branch
    // should never be taken - and "should" is not what may stand between
    // a bad index and a read past the end.
    return i < hs.count ? &hs.items[i] : nullptr;
}
} // namespace http

// RFC 9110 12.5: see the declaration - the values negotiation reads, out of
// the fields a parked stream copied, which is the only place they still are.
void values_of_copied_fields(http::HeaderList h, http::ReqValues &out)
{
    flow::ReqFacts scratch;
    for (size_t i = 0; i < h.count; i++) {
        http::header_switch(
            {{h.items[i].name, h.items[i].name_len}, {h.items[i].value, h.items[i].value_len}},
            {scratch, out, i});
    }
}

} // namespace webmachine
