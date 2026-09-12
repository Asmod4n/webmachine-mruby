#include "webmachine.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>

#include "mime_builtin.h"

namespace webmachine
{
namespace
{
using ExtType = std::pair<std::string, std::string>;

// The extension order type_of then searches in. Types, not function
// pointers: the sort inlines the comparison the way it did the lambdas.
struct ExtBefore {
    bool operator()(const ExtType &a, const ExtType &b) const
    {
        return a.first < b.first;
    }
};
struct SameExt {
    bool operator()(const ExtType &a, const ExtType &b) const
    {
        return a.first == b.first;
    }
};
struct ExtBeforeKey {
    bool operator()(const ExtType &a, const std::string &b) const
    {
        return a.first < b;
    }
};

// POSIX read(2): a whole file into memory. Setup only.
bool file_read_whole(const char *path, std::string &text)
{
    const int opened_fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (opened_fd < 0)
        return false;
    char chunk[64 * 1024];
    for (;;) {
        const ssize_t got = ::read(opened_fd, chunk, sizeof chunk);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            ::close(opened_fd);
            return false;
        }
        if (got == 0)
            break;
        text.append(chunk, static_cast<size_t>(got));
    }
    ::close(opened_fd);
    return true;
}

// Apache mime.types / shared-mime-info globs2: field separators.
bool character_is_blank(char character)
{
    return character == ' ' || character == '\t' || character == '\r';
}

// RFC 9110 8.3: a media type's extension key is case-insensitive.
char character_lowercased(char character)
{
    return character >= 'A' && character <= 'Z' ? char(character - 'A' + 'a') : character;
}
} // namespace

// RFC 9110 8.3: one extension, one media type.
void MimeDb::take(const char *type, size_t tlen, const char *extension, size_t elen)
{
    if (tlen == 0 || elen == 0)
        return;
    std::string key(elen, '\0');
    for (size_t i = 0; i < elen; i++)
        key[i] = character_lowercased(extension[i]);
    by_ext_.emplace_back(std::move(key), std::string(type, tlen));
}

// Apache mime.types format: "type ext ext ...", '#' comments.
void MimeDb::parse_types(const char *cursor, const char *text_end)
{
    while (cursor < text_end) {
        const char *line_end =
            static_cast<const char *>(std::memchr(cursor, '\n', size_t(text_end - cursor)));
        const char *stop = line_end != nullptr ? line_end : text_end;
        const char *hash =
            static_cast<const char *>(std::memchr(cursor, '#', size_t(stop - cursor)));
        if (hash != nullptr)
            stop = hash;
        while (cursor < stop && character_is_blank(*cursor))
            cursor++;
        const char *type = cursor;
        while (cursor < stop && !character_is_blank(*cursor))
            cursor++;
        const size_t tlen = size_t(cursor - type);
        while (cursor < stop) {
            while (cursor < stop && character_is_blank(*cursor))
                cursor++;
            const char *extension = cursor;
            while (cursor < stop && !character_is_blank(*cursor))
                cursor++;
            take(type, tlen, extension, size_t(cursor - extension));
        }
        if (line_end == nullptr)
            break;
        cursor = line_end + 1;
    }
}

// shared-mime-info globs2 format: "weight:type:*.ext".
void MimeDb::parse_globs2(const char *cursor, const char *text_end)
{
    while (cursor < text_end) {
        const char *line_end =
            static_cast<const char *>(std::memchr(cursor, '\n', size_t(text_end - cursor)));
        const char *stop = line_end != nullptr ? line_end : text_end;
        if (cursor < stop && *cursor != '#') {
            const char *first_colon =
                static_cast<const char *>(std::memchr(cursor, ':', size_t(stop - cursor)));
            if (first_colon != nullptr) {
                const char *type = first_colon + 1;
                const char *second_colon =
                    static_cast<const char *>(std::memchr(type, ':', size_t(stop - type)));
                if (second_colon != nullptr) {
                    const char *glob = second_colon + 1;
                    const size_t glen = size_t(stop - glob);
                    if (glen > 2 && glob[0] == '*' && glob[1] == '.' &&
                        std::memchr(glob + 2, '*', glen - 2) == nullptr &&
                        std::memchr(glob + 2, '?', glen - 2) == nullptr &&
                        std::memchr(glob + 2, '[', glen - 2) == nullptr) {
                        take(type, size_t(second_colon - type), glob + 2, glen - 2);
                    }
                }
            }
        }
        if (line_end == nullptr)
            break;
        cursor = line_end + 1;
    }
}

// RFC 9110 8.3: the machine's own media-type database, first that exists.
void MimeDb::load(mrb_state *mrb, const char *configured)
{
    static const char *const kTypesPaths[] = {"/etc/mime.types", "/etc/apache2/mime.types",
                                              "/etc/httpd/conf/mime.types",
                                              "/usr/local/etc/mime.types"};
    static const char kGlobs2[] = "/usr/share/mime/globs2";

    std::string text;
    bool globs2 = false;
    if (configured != nullptr && configured[0] != '\0') {
        if (!file_read_whole(configured, text)) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "media types: %s: %s", configured,
                       std::strerror(errno));
        }
        source_ = configured;
        globs2 = source_.size() >= 6 && source_.compare(source_.size() - 6, 6, "globs2") == 0;
    } else {
        for (const char *path : kTypesPaths) {
            if (file_read_whole(path, text)) {
                source_ = path;
                break;
            }
        }
        if (source_.empty() && file_read_whole(kGlobs2, text)) {
            source_ = kGlobs2;
            globs2 = true;
        }
        if (source_.empty()) {
            text.assign(kBuiltinMimeTypes, sizeof(kBuiltinMimeTypes) - 1);
            source_ = "built in (share/mime.types)";
        }
    }

    const char *cursor = text.data();
    const char *text_end = cursor + text.size();
    if (globs2) {
        parse_globs2(cursor, text_end);
    } else {
        parse_types(cursor, text_end);
    }

    std::stable_sort(by_ext_.begin(), by_ext_.end(), ExtBefore());
    by_ext_.erase(std::unique(by_ext_.begin(), by_ext_.end(), SameExt()), by_ext_.end());

    if (by_ext_.empty()) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "media types: %s holds no extension at all",
                   source_.c_str());
    }
}

// RFC 9110 8.3: the type a filename claims; octet-stream when unknown.
const char *MimeDb::type_of(const std::string &name) const
{
    static const char kOctets[] = "application/octet-stream";
    const size_t last_dot = name.rfind('.');
    if (last_dot == std::string::npos || last_dot + 1 == name.size())
        return kOctets;
    std::string ext(name.size() - last_dot - 1, '\0');
    for (size_t i = 0; i < ext.size(); i++)
        ext[i] = character_lowercased(name[last_dot + 1 + i]);
    const auto found = std::lower_bound(by_ext_.begin(), by_ext_.end(), ext, ExtBeforeKey());
    return found != by_ext_.end() && found->first == ext ? found->second.c_str() : kOctets;
}
} // namespace webmachine
