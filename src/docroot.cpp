// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <sys/stat.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace webmachine {
namespace {
// One process, one docroot: the fd RESOLVE_BENEATH anchors against has to
// outlive every request, and a second one would be a second answer to
// "beneath what".
std::string root_;
int fd_ = -1;
struct open_how how_ {};
}

// The canonical path and the dirfd, ONCE, before the first accept. Canonical
// matters: a relative or symlink-carrying docroot would make "beneath" mean
// whatever the cwd or the link says today, and the confinement is only worth
// as much as the thing it is anchored to.
bool docroot_open(const char* path, Refusal why) {
  char* const err = why.buf;
  const size_t errlen = why.len;
  char real[PATH_MAX];
  if (::realpath(path, real) == nullptr) {
    std::snprintf(err, errlen, "--docroot %s: %s", path, std::strerror(errno));
    return false;
  }
  struct stat st {};
  if (::stat(real, &st) != 0) {
    std::snprintf(err, errlen, "--docroot %s: %s", real, std::strerror(errno));
    return false;
  }
  if (!S_ISDIR(st.st_mode)) {
    std::snprintf(err, errlen, "--docroot %s is not a directory", real);
    return false;
  }
  // O_PATH is all a dirfd owes openat2: it names the anchor, it never reads.
  const int fd = ::open(real, O_DIRECTORY | O_PATH | O_CLOEXEC);
  if (fd < 0) {
    std::snprintf(err, errlen, "--docroot %s: %s", real, std::strerror(errno));
    return false;
  }
  if (fd_ >= 0) ::close(fd_);
  fd_ = fd;
  root_ = real;
  // O_NONBLOCK so a FIFO planted in the docroot answers instead of parking an
  // io-wq worker on a writer that never comes; statx refuses it right after.
  how_.flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
  how_.mode = 0;
  how_.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
  return true;
}

bool docroot_ready() { return fd_ >= 0; }

int docroot_fd() { return fd_; }

const char* docroot_path() { return root_.c_str(); }

const struct open_how* docroot_how() { return &how_; }
}
