#include "webmachine.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>

#include "mime_builtin.h"

namespace webmachine {
namespace {

bool slurp(const char* path, std::string& out) {
  const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  char buf[64 * 1024];
  for (;;) {
    const ssize_t n = ::read(fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      return false;
    }
    if (n == 0) break;
    out.append(buf, static_cast<size_t>(n));
  }
  ::close(fd);
  return true;
}

bool blank(char c) { return c == ' ' || c == '\t' || c == '\r'; }

char lower(char c) { return c >= 'A' && c <= 'Z' ? char(c - 'A' + 'a') : c; }

}  // namespace

void MimeDb::take(const char* type, size_t tlen, const char* ext, size_t elen) {
  if (tlen == 0 || elen == 0) return;
  std::string key(elen, '\0');
  for (size_t i = 0; i < elen; i++) key[i] = lower(ext[i]);
  by_ext_.emplace_back(std::move(key), std::string(type, tlen));
}

// "type ext ext ..." - a media type, then the extensions that mean it.
// Everything from '#' is a comment; a line with no extension names a
// registered type that cannot answer a lookup, and is skipped.
void MimeDb::parse_types(const char* p, const char* end) {
  while (p < end) {
    const char* eol = static_cast<const char*>(std::memchr(p, '\n', size_t(end - p)));
    const char* stop = eol != nullptr ? eol : end;
    const char* hash = static_cast<const char*>(std::memchr(p, '#', size_t(stop - p)));
    if (hash != nullptr) stop = hash;
    while (p < stop && blank(*p)) p++;
    const char* type = p;
    while (p < stop && !blank(*p)) p++;
    const size_t tlen = size_t(p - type);
    while (p < stop) {
      while (p < stop && blank(*p)) p++;
      const char* ext = p;
      while (p < stop && !blank(*p)) p++;
      take(type, tlen, ext, size_t(p - ext));
    }
    if (eol == nullptr) break;
    p = eol + 1;
  }
}

// shared-mime-info's globs2: "weight:type:glob". Only "*.ext" is taken
// - a glob with any other wildcard names a whole filename pattern, and
// this table is keyed by extension. The weight is read and ignored:
// the file is already sorted by it, so a later row for the same
// extension is the weaker claim and simply loses to the earlier one at
// dedup time.
void MimeDb::parse_globs2(const char* p, const char* end) {
  while (p < end) {
    const char* eol = static_cast<const char*>(std::memchr(p, '\n', size_t(end - p)));
    const char* stop = eol != nullptr ? eol : end;
    if (p < stop && *p != '#') {
      const char* c1 = static_cast<const char*>(std::memchr(p, ':', size_t(stop - p)));
      if (c1 != nullptr) {
        const char* type = c1 + 1;
        const char* c2 = static_cast<const char*>(std::memchr(type, ':', size_t(stop - type)));
        if (c2 != nullptr) {
          const char* glob = c2 + 1;
          const size_t glen = size_t(stop - glob);
          if (glen > 2 && glob[0] == '*' && glob[1] == '.' &&
              std::memchr(glob + 2, '*', glen - 2) == nullptr &&
              std::memchr(glob + 2, '?', glen - 2) == nullptr &&
              std::memchr(glob + 2, '[', glen - 2) == nullptr) {
            take(type, size_t(c2 - type), glob + 2, glen - 2);
          }
        }
      }
    }
    if (eol == nullptr) break;
    p = eol + 1;
  }
}

bool MimeDb::load(const char* configured, char* err, size_t errlen) {
  static const char* const kTypesPaths[] = {
      "/etc/mime.types", "/etc/apache2/mime.types", "/etc/httpd/conf/mime.types",
      "/usr/local/etc/mime.types"};
  static const char kGlobs2[] = "/usr/share/mime/globs2";

  std::string text;
  bool globs2 = false;
  if (configured != nullptr && configured[0] != '\0') {
    if (!slurp(configured, text)) {
      std::snprintf(err, errlen, "media types: %s: %s", configured, std::strerror(errno));
      return false;
    }
    source_ = configured;
    // The operator's file is read as whichever format its NAME says -
    // globs2 is the only one with a distinct one, and it is always
    // called that.
    globs2 = source_.size() >= 6 && source_.compare(source_.size() - 6, 6, "globs2") == 0;
  } else {
    for (const char* path : kTypesPaths) {
      if (slurp(path, text)) {
        source_ = path;
        break;
      }
    }
    if (source_.empty() && slurp(kGlobs2, text)) {
      source_ = kGlobs2;
      globs2 = true;
    }
    if (source_.empty()) {
      text.assign(kBuiltinMimeTypes, sizeof(kBuiltinMimeTypes) - 1);
      source_ = "built in (share/mime.types)";
    }
  }

  const char* p = text.data();
  const char* end = p + text.size();
  if (globs2) {
    parse_globs2(p, end);
  } else {
    parse_types(p, end);
  }

  // Sorted for the binary search, and deduplicated so one extension
  // holds one type. std::stable_sort keeps the file's own order among
  // equal keys, which is what makes "the first row wins" mean "the
  // first row of the file" - globs2's weight ordering and a
  // mime.types duplicate both resolve the same way.
  std::stable_sort(by_ext_.begin(), by_ext_.end(),
                   [](const std::pair<std::string, std::string>& a,
                      const std::pair<std::string, std::string>& b) { return a.first < b.first; });
  by_ext_.erase(std::unique(by_ext_.begin(), by_ext_.end(),
                            [](const std::pair<std::string, std::string>& a,
                               const std::pair<std::string, std::string>& b) {
                              return a.first == b.first;
                            }),
                by_ext_.end());

  if (by_ext_.empty()) {
    std::snprintf(err, errlen, "media types: %s holds no extension at all", source_.c_str());
    return false;
  }
  return true;
}

const char* MimeDb::type_of(const std::string& name) const {
  static const char kOctets[] = "application/octet-stream";
  const size_t dot = name.rfind('.');
  if (dot == std::string::npos || dot + 1 == name.size()) return kOctets;
  std::string ext(name.size() - dot - 1, '\0');
  for (size_t i = 0; i < ext.size(); i++) ext[i] = lower(name[dot + 1 + i]);
  const auto it = std::lower_bound(by_ext_.begin(), by_ext_.end(), ext,
                                   [](const std::pair<std::string, std::string>& a,
                                      const std::string& b) { return a.first < b; });
  return it != by_ext_.end() && it->first == ext ? it->second.c_str() : kOctets;
}

}  // namespace webmachine
