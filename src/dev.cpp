// Design decisions live in .DESIGN.md, filed under what each comment names.
//
// DEV MODE: the folder somebody is editing, served as it lies.
//
// A site in production is a pack: every file named by its content, the
// plain name beside it, one mapping, nothing read from disk per request.
// That is the wrong shape for the loop somebody edits in - a rebuild per
// keystroke, and a name that changes with every save.
//
// ONE COPY OF THE SITE, AND IT IS THE FOLDER. A mirror in a temporary
// directory was the first shape of this and it is a split brain: two
// copies, a watcher between them, and every gap in it serves bytes the
// source no longer has - which is worst at the end, because the pack is
// written from the source and not from what was served. So the docroot
// IS the folder, and nothing is copied anywhere.
//
// The one thing a page needs that a plain file cannot give is
// {{asset:/path}}, the spelling that names a file it embeds. In a pack
// that becomes the hashed name. Here it becomes the plain path, filled
// as the page is answered - so a stylesheet that changes rewrites
// nothing, and what the browser gets came from the file that is on disk
// right now.
//
// The pack is written ONCE, when the server quits, from the same folder,
// and appended to whatever pack is already there - so every hashed name
// a browser wrote down in an earlier session keeps answering. Iterate as
// often as you like; the artefact is built at the end, by the same tree
// that serves it.
#include "webmachine.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <climits>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

namespace webmachine {
namespace {

// The folder this mode serves. One process, one folder - the docroot is
// anchored to it, and a second one would make "beneath what" ambiguous.
std::string source_;

// {{asset:PATH}} - the one spelling a page uses to name a file it embeds.
// In a pack that becomes the hashed name; here it becomes the plain path,
// because a dev loop wants the name it typed.
constexpr char kTagOpen[] = "{{asset:";
constexpr size_t kTagOpenLen = sizeof(kTagOpen) - 1;

// What a page may weigh before this stops filling it. A file this big is
// not a page, so it is served as it lies. The tag stays visible on the
// page, which is how a reader hears about it.
constexpr size_t kFillMax = 4u * 1024 * 1024;

// The whole file, or empty when it cannot be read.
std::string slurp(const std::string& path) {
  std::string out;
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return out;
  char buf[65536];
  ssize_t got;
  while ((got = ::read(fd, buf, sizeof(buf))) > 0) out.append(buf, static_cast<size_t>(got));
  ::close(fd);
  return out;
}

bool text_name(const std::string& name) {
  static const char* const kText[] = {".html", ".htm", ".css",  ".js",  ".mjs",
                                      ".svg",  ".json", ".txt", ".xml", ".webmanifest"};
  const size_t dot = name.rfind('.');
  if (dot == std::string::npos) return false;
  for (const char* ext : kText) {
    if (name.compare(dot, std::string::npos, ext) == 0) return true;
  }
  return false;
}
}  // namespace

// The folder, checked once. Answers its canonical path, or an empty
// string when it is not a directory this process can read - the caller
// says so and does not start.
std::string dev_open(const char* dir) {
  char real[PATH_MAX];
  if (dir == nullptr || ::realpath(dir, real) == nullptr) return std::string();
  struct stat st {};
  if (::stat(real, &st) != 0 || !S_ISDIR(st.st_mode)) return std::string();
  source_.assign(real);
  return source_;
}

// Is this a name whose {{asset:...}} tags this mode fills? Only text, and
// only in dev: a pack fills them when it is written, and a plain docroot
// has no tags to fill.
bool dev_fills(const char* name, size_t len) {
  return !source_.empty() && text_name(std::string(name, len));
}

// The file, with every tag filled in. Answers false when the file cannot
// be read or is too big to be a page, and the caller then serves it as it
// lies. A path the folder does not hold is left as it was written: a dev
// loop says so on the page, where the person who typed it is looking.
bool dev_fill(const char* name, size_t len, std::string& out) {
  if (source_.empty()) return false;
  const std::string path = source_ + "/" + std::string(name, len);
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
  if (static_cast<size_t>(st.st_size) > kFillMax) return false;

  const std::string body = slurp(path);
  if (body.empty()) return false;
  if (body.find(kTagOpen) == std::string::npos) return false;

  out.clear();
  out.reserve(body.size());
  size_t at = 0;
  for (;;) {
    const size_t open = body.find(kTagOpen, at);
    if (open == std::string::npos) {
      out.append(body, at, std::string::npos);
      return true;
    }
    const size_t close = body.find("}}", open);
    if (close == std::string::npos) {
      out.append(body, at, std::string::npos);
      return true;
    }
    std::string named = body.substr(open + kTagOpenLen, close - open - kTagOpenLen);
    while (!named.empty() && (named.front() == ' ' || named.front() == '\t')) named.erase(0, 1);
    while (!named.empty() && (named.back() == ' ' || named.back() == '\t')) named.pop_back();
    out.append(body, at, open - at);
    out.append(named);
    at = close + 2;
  }
}

// The folder this mode serves, for whoever writes the pack at the end.
const char* dev_source() { return source_.empty() ? nullptr : source_.c_str(); }

void dev_close() { source_.clear(); }
}  // namespace webmachine
