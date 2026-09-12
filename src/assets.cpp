#include "webmachine.hpp"

#include <miniz.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace webmachine
{
namespace
{
// The order find_exact then searches in. A type, not a function pointer:
// the sort inlines the comparison the way it did the lambda this replaced.
struct ByFileName {
    bool operator()(const AssetEntry &one, const AssetEntry &other) const
    {
        return one.file_name < other.file_name;
    }
};

// The same order against a name that is not an entry yet.
struct NameBeforeKey {
    bool operator()(const AssetEntry &row, const std::pair<const char *, size_t> &key) const
    {
        const size_t shortest =
            row.file_name.size() < key.second ? row.file_name.size() : key.second;
        const int compared = std::memcmp(row.file_name.data(), key.first, shortest);
        if (compared != 0)
            return compared < 0;
        return row.file_name.size() < key.second;
    }
};

// APPNOTE 4.4.7: the CRC-32 the pack stored against the octets it holds.
// A gzip answer ships that number as its trailer and the ETag spells it,
// so a pack that disagrees with itself makes every client throw the body
// away. The check reads each asset once at start and never again.
bool entry_crc_is_right(const char *data, size_t comp, size_t uncomp, bool deflated, uint32_t want)
{
    if (comp > 0xffffffffu || uncomp > 0xffffffffu)
        return false;
    const unsigned char *const input = reinterpret_cast<const unsigned char *>(data);
    if (!deflated) {
        if (comp != uncomp)
            return false;
        return static_cast<uint32_t>(mz_crc32(MZ_CRC32_INIT, input, comp)) == want;
    }
    mz_stream stream = {};
    if (mz_inflateInit2(&stream, -MZ_DEFAULT_WINDOW_BITS) != MZ_OK)
        return false;
    unsigned char scratch[16u * 1024u];
    mz_ulong running_crc = MZ_CRC32_INIT;
    size_t out_total = 0;
    stream.next_in = input;
    stream.avail_in = static_cast<unsigned int>(comp);
    int status = MZ_OK;
    for (;;) {
        stream.next_out = scratch;
        stream.avail_out = static_cast<unsigned int>(sizeof(scratch));
        status = mz_inflate(&stream, MZ_SYNC_FLUSH);
        const size_t got = sizeof(scratch) - stream.avail_out;
        running_crc = mz_crc32(running_crc, scratch, got);
        out_total += got;
        if (status != MZ_OK)
            break;
        if (got == 0 && stream.avail_in == 0)
            break;
    }
    mz_inflateEnd(&stream);
    return status == MZ_STREAM_END && out_total == uncomp &&
           static_cast<uint32_t>(running_crc) == want;
}

// RFC 9110 5.6.7: the archive's mtime as Last-Modified; 0 serves none.
bool mtime_spell_imf_date(time_t mtime, char out_date[http::kDateLen])
{
    if (mtime <= 0)
        return false;
    struct tm norm;
    if (gmtime_r(&mtime, &norm) == nullptr)
        return false;
    http::date_core(out_date, norm);
    return true;
}

// RFC 9110 8.8.3: the CRC-32 an ETag is spelled from.
void hex8_spell(char *out_hex, uint32_t value)
{
    static const char kHex[] = "0123456789abcdef";
    for (int i = 7; i >= 0; i--) {
        out_hex[i] = kHex[value & 0xf];
        value >>= 4;
    }
}

// APPNOTE 4.5.2: an extra field block is a run of (id, size, payload),
// and a reader skips the ids it does not know. 0x574D is this tree's,
// written by the error_assets task: the finished <img> for the picture,
// so nothing here has a URL to join or a number to spell.
constexpr uint16_t kExtraImgTag = 0x574d;

// 0x574E is the second, written by the pack task: the Cache-Control
// value for this entry. A lifetime belongs to the file rather than to
// the server - a hashed bundle may be kept for a year, an index.html
// for a minute. The pack says it once, the head is built with it at
// open, and no request reads it.
constexpr uint16_t kExtraCacheControl = 0x574e;

// 0x574F is the table the pack task writes. An entry there is named by a
// hash of its content - index.4f3a1c9d2b70.html - and this field holds
// the name a client actually asks for: index.html. The pack therefore
// holds one copy of the bytes under two names, and the two names get
// different answers, which is the whole point of hashing a name:
//
//   the hashed name cannot ever mean other bytes, so it says the maximum
//   a cache may hold and is never asked about again;
//
//   the plain name means whatever is there now, so it says what the
//   person who packed the site decided (field 0x574E).
constexpr uint16_t kExtraPlainName = 0x574f;

// RFC 9111 5.2.2.1: what a name that cannot change is worth saying.
constexpr const char kImmutable[] = "public, max-age=31536000, immutable";

struct Borrowed {
    const char *text = nullptr;
    size_t length = 0;
};

// APPNOTE 4.5.2: walk the blocks, answer the one id asked for.
Borrowed extra_field_find(const unsigned char *extra, size_t extra_length, uint16_t want)
{
    Borrowed borrowed;
    size_t offset = 0;
    while (offset + 4 <= extra_length) {
        const uint16_t field_id = MZ_READ_LE16(extra + offset);
        const size_t size = MZ_READ_LE16(extra + offset + 2);
        if (offset + 4 + size > extra_length)
            break;
        if (field_id == want && size != 0) {
            borrowed.text = reinterpret_cast<const char *>(extra + offset + 4);
            borrowed.length = size;
            break;
        }
        offset += 4 + size;
    }
    return borrowed;
}

// The parts of one prebuilt header section: the status line, the
// Connection field of the spelling being built, and the entry's own fields.
struct HeadParts {
    const char *status_line;
    const char *connection_line;
    const std::string &fields;
};

// RFC 9112: one prebuilt header section, Date placeholder at a kept offset.
void head_build(AssetEntry::Head &out_head, const HeadParts &parts)
{
    out_head.bytes.clear();
    out_head.bytes.append(parts.status_line);
    out_head.bytes.append("\r\nDate: ");
    out_head.date_offset = out_head.bytes.size();
    out_head.bytes.append(http::kDatePlaceholder, http::kDateLen);
    out_head.bytes.append("\r\n").append(parts.connection_line).append(parts.fields).append("\r\n");
    out_head.unix_seconds = 0;
}

// RFC 9112 9.3: the same head in all three connection spellings.
// RFC 9110 15.5.6 and 12.5.3: what these two refusals carry besides the
// status - the same fields whether the answer has a page behind them or
// not, which is why they are named once and spelled twice.
constexpr char kStatus405[] = "HTTP/1.1 405 Method Not Allowed";
constexpr char kStatus406[] = "HTTP/1.1 406 Not Acceptable";
constexpr char kAllowField[] = "Allow: GET, HEAD\r\n";
constexpr char kVaryField[] = "Vary: Accept-Encoding\r\n";

void head_build_all_three(AssetEntry::Head (&h)[3], HeadParts parts)
{
    for (uint8_t coding = Assets::kNoConnectionField; coding <= Assets::kConnClose; coding++) {
        parts.connection_line = Assets::kConnectionLine[coding];
        head_build(h[coding], parts);
    }
}
} // namespace

// The mapping is what serves, and it serves until the process ends.
Assets::~Assets()
{
    if (map_addr_ != nullptr)
        ::munmap(const_cast<char *>(map_addr_), map_length_);
}

// ZIP (APPNOTE): archive in, entry table + prebuilt responses out. miniz
// parses; this reads only the 30-byte Local Header, to skip it.
void Assets::open(mrb_state *mrb, const char *zip_path, const MimeDb &mime)
{
    const int opened_fd = ::open(zip_path, O_RDONLY | O_CLOEXEC);
    if (opened_fd < 0) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %s", zip_path, std::strerror(errno));
    }
    struct stat info;
    if (::fstat(opened_fd, &info) != 0 || info.st_size < 22) {
        ::close(opened_fd);
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: not a ZIP (too small for an end record)",
                   zip_path);
    }
    map_length_ = static_cast<size_t>(info.st_size);
    void *mapped = ::mmap(nullptr, map_length_, PROT_READ, MAP_PRIVATE, opened_fd, 0);
    ::close(opened_fd);
    if (mapped == MAP_FAILED) {
        map_length_ = 0;
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "mmap %s: %s", zip_path, std::strerror(errno));
    }
    map_addr_ = static_cast<const char *>(mapped);
    const unsigned char *base = reinterpret_cast<const unsigned char *>(map_addr_);

    mz_zip_archive zip_archive;
    std::memset(&zip_archive, 0, sizeof(zip_archive));
    if (!mz_zip_reader_init_mem(&zip_archive, map_addr_, map_length_, 0)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: not a readable ZIP (%s)", zip_path,
                   mz_zip_get_error_string(mz_zip_get_last_error(&zip_archive)));
    }
    struct Ender {
        mz_zip_archive *zip_reader;
        // miniz's reader is a setup tool and ends with this scope.
        ~Ender()
        {
            mz_zip_reader_end(zip_reader);
        }
    } ender{&zip_archive};

    const mz_uint member_count = mz_zip_reader_get_num_files(&zip_archive);
    if (member_count >= 0xffff) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "%s: %d entries - Zip64 territory, excluded by design", zip_path,
                   static_cast<int>(member_count));
    }
    entries_.reserve(member_count);

    for (mz_uint i = 0; i < member_count; i++) {
        mz_zip_archive_file_stat member_stat;
        if (!mz_zip_reader_file_stat(&zip_archive, i, &member_stat)) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: entry %d: %s", zip_path,
                       static_cast<int>(i),
                       mz_zip_get_error_string(mz_zip_get_last_error(&zip_archive)));
        }
        const size_t nlen = std::strlen(member_stat.m_filename);

        if (member_stat.m_is_directory)
            continue;
        if (member_stat.m_is_encrypted) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %s is encrypted - not supported", zip_path,
                       member_stat.m_filename);
        }
        if (member_stat.m_method != 0 && member_stat.m_method != MZ_DEFLATED) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                       "%s: %s uses method %d - only stored (0) and deflate (8) are served",
                       zip_path, member_stat.m_filename, static_cast<int>(member_stat.m_method));
        }
        if (member_stat.m_comp_size > 0xffffffffULL || member_stat.m_uncomp_size > 0xffffffffULL) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                       "%s: %s is 4 GB or larger - Zip64, excluded by "
                       "design",
                       zip_path, member_stat.m_filename);
        }

        const size_t local_header_offset = static_cast<size_t>(member_stat.m_local_header_ofs);
        if (local_header_offset + 30 > map_length_ ||
            MZ_READ_LE32(base + local_header_offset) != 0x04034b50) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %s has a broken local header", zip_path,
                       member_stat.m_filename);
        }
        const size_t extra_off =
            local_header_offset + 30 + MZ_READ_LE16(base + local_header_offset + 26);
        const size_t extra_len = MZ_READ_LE16(base + local_header_offset + 28);
        const size_t data_off = extra_off + extra_len;
        const size_t comp = static_cast<size_t>(member_stat.m_comp_size);
        if (data_off + comp > map_length_) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %s data overruns the file", zip_path,
                       member_stat.m_filename);
        }

        AssetEntry entry;
        entry.file_name.assign(member_stat.m_filename, nlen);
        entry.file_data = map_addr_ + data_off;
        entry.compressed_size = comp;
        entry.uncompressed_size = static_cast<size_t>(member_stat.m_uncomp_size);
        entry.crc32 = member_stat.m_crc32;
        entry.deflated = member_stat.m_method == MZ_DEFLATED;
        if (!entry_crc_is_right(entry.file_data, entry.compressed_size, entry.uncompressed_size,
                                entry.deflated, entry.crc32)) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                       "%s: %s does not hold the octets the pack claims", zip_path,
                       member_stat.m_filename);
        }
        entry.last_modified_valid = mtime_spell_imf_date(member_stat.m_time, entry.last_modified);
        entry.etag[0] = '"';
        hex8_spell(entry.etag + 1, member_stat.m_crc32);
        entry.etag[9] = '"';
        const Borrowed etag = extra_field_find(base + extra_off, extra_len, kExtraImgTag);
        entry.img_tag = etag.text;
        entry.img_tag_len = etag.length;
        const Borrowed cache_control =
            extra_field_find(base + extra_off, extra_len, kExtraCacheControl);
        // RFC 9110 5.6.2: a field value is visible ASCII and space. A pack
        // that carries anything else does not get to spell a header field.
        bool cc_ok = cache_control.length != 0;
        for (size_t k = 0; k < cache_control.length; k++) {
            const unsigned char character = static_cast<unsigned char>(cache_control.text[k]);
            if (character < 0x20 || character > 0x7e)
                cc_ok = false;
        }
        if (cache_control.length != 0 && !cc_ok) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                       "%s: %s carries a Cache-Control that is not a field value", zip_path,
                       member_stat.m_filename);
        }
        // The pack's table: this entry is named by its content, and the
        // plain name beside it is what a client asks for. Both are answered,
        // from these bytes, with the two lifetimes they deserve.
        const Borrowed plain = extra_field_find(base + extra_off, extra_len, kExtraPlainName);
        if (plain.length != 0) {
            AssetEntry alias = entry;
            alias.file_name.assign(plain.text, plain.length);
            if (cc_ok)
                alias.cache_control.assign(cache_control.text, cache_control.length);
            entry.cache_control.assign(kImmutable);
            entries_.push_back(std::move(alias));
        } else if (cc_ok) {
            entry.cache_control.assign(cache_control.text, cache_control.length);
        }
        entries_.push_back(std::move(entry));
    }

    std::stable_sort(entries_.begin(), entries_.end(), ByFileName());
    for (size_t i = 0; i + 1 < entries_.size();) {
        if (entries_[i].file_name == entries_[i + 1].file_name)
            entries_.erase(entries_.begin() + i);
        else
            i++;
    }

    for (AssetEntry &e : entries_) {
        e.content_type = http::with_charset(mime.type_of(e.file_name));
        std::string file_entry;
        file_entry.append("Content-Type: ").append(e.content_type).append("\r\n");
        if (e.deflated) {
            file_entry.append("Content-Encoding: gzip\r\n");
            file_entry.append("Vary: Accept-Encoding\r\n");
        }
        file_entry.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
        if (e.last_modified_valid) {
            file_entry.append("Last-Modified: ")
                .append(e.last_modified, sizeof(e.last_modified))
                .append("\r\n");
        }
        if (!e.cache_control.empty()) {
            file_entry.append("Cache-Control: ").append(e.cache_control).append("\r\n");
        }
        file_entry.append("Accept-Ranges: bytes\r\n");
        const size_t clen = e.deflated ? e.compressed_size + 18 : e.compressed_size;
        file_entry.append("Content-Length: ").append(std::to_string(clen)).append("\r\n");
        head_build_all_three(e.head_200, {"HTTP/1.1 200 OK", nullptr, file_entry});

        std::string f304;
        f304.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
        // RFC 9111 4.3.4: what a 304 carries updates the stored response, and
        // the freshness lifetime is the field a cache most needs updated.
        if (!e.cache_control.empty()) {
            f304.append("Cache-Control: ").append(e.cache_control).append("\r\n");
        }
        if (e.deflated)
            f304.append("Vary: Accept-Encoding\r\n");
        head_build_all_three(e.head_304, {"HTTP/1.1 304 Not Modified", nullptr, f304});

        if (e.deflated) {
            static const unsigned char kGzHdr[10] = {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff};
            std::memcpy(e.gzip_header, kGzHdr, sizeof(kGzHdr));
            e.gzip_trailer[0] = static_cast<unsigned char>(e.crc32);
            e.gzip_trailer[1] = static_cast<unsigned char>(e.crc32 >> 8);
            e.gzip_trailer[2] = static_cast<unsigned char>(e.crc32 >> 16);
            e.gzip_trailer[3] = static_cast<unsigned char>(e.crc32 >> 24);
            e.gzip_trailer[4] = static_cast<unsigned char>(e.uncompressed_size);
            e.gzip_trailer[5] = static_cast<unsigned char>(e.uncompressed_size >> 8);
            e.gzip_trailer[6] = static_cast<unsigned char>(e.uncompressed_size >> 16);
            e.gzip_trailer[7] = static_cast<unsigned char>(e.uncompressed_size >> 24);
        }
    }

    head_build_all_three(s405_,
                         {kStatus405, nullptr, std::string(kAllowField) + "Content-Length: 0\r\n"});
    head_build_all_three(s406_,
                         {kStatus406, nullptr, std::string(kVaryField) + "Content-Length: 0\r\n"});
}

// One entry, by name, exact bytes.
const AssetEntry *Assets::find_exact(const char *name, size_t name_length) const
{
    const auto found =
        std::lower_bound(entries_.begin(), entries_.end(),
                         std::pair<const char *, size_t>(name, name_length), NameBeforeKey());
    if (found == entries_.end() || found->file_name.size() != name_length ||
        std::memcmp(found->file_name.data(), name, name_length) != 0) {
        return nullptr;
    }
    return &*found;
}

// RFC 9110 4.2.1: the target names a table row, byte for byte - or, for a
// path that names a directory (root "/", or anything ending "/"), that
// directory's own index.html, the near-universal default document. A pack
// with no index.html at that path answers 404 exactly as before; nothing
// here invents a directory listing.
AssetEntry *Assets::find(const char *path, size_t path_length)
{
    if (path_length == 0 || path[0] != '/')
        return nullptr;
    path++;
    path_length--;
    for (size_t i = 0; i < path_length; i++) {
        if (path[i] == '?') {
            path_length = i;
            break;
        }
    }
    if (path_length == 0 || path[path_length - 1] == '/') {
        static constexpr char kIndex[] = "index.html";
        static constexpr size_t kIndexLen = sizeof(kIndex) - 1;
        char with_index[kMaxHead];
        if (path_length + kIndexLen > sizeof(with_index))
            return nullptr;
        if (path_length != 0)
            std::memcpy(with_index, path, path_length);
        std::memcpy(with_index + path_length, kIndex, kIndexLen);
        return const_cast<AssetEntry *>(find_exact(with_index, path_length + kIndexLen));
    }
    return const_cast<AssetEntry *>(find_exact(path, path_length));
}

// RFC 9110: the asset tier's whole decision, in the graph's own order -
// 405/501, 406 (12.5.3+15.5.7), 412 (13.1.1), 304 (13.1.2), else 200.
uint16_t Assets::entry_verdict(const AssetEntry &entry, const AssetRequest &request) const
{
    const flow::ReqFacts &fresh = request.facts;
    const http::ReqValues &vals = request.vals;
    switch (fresh.method) {
        case flow::Method::kGet:
        case flow::Method::kHead:
            break;
        case flow::Method::kOther:
            return 501;
        default:
            return 405;
    }
    if (entry.deflated && fresh.has_accept_encoding &&
        !http::gzip_acceptable(vals.accept_encoding, vals.accept_encoding_len)) {
        return 406;
    }
    if (fresh.has_if_match && !fresh.if_match_star &&
        !http::etag_list_match(
            {{vals.if_match, vals.if_match_len}, {entry.etag, sizeof(entry.etag)}, false})) {
        return 412;
    }
    if (fresh.has_if_none_match &&
        (fresh.if_none_match_star ||
         http::etag_list_match({{vals.if_none_match, vals.if_none_match_len},
                                {entry.etag, sizeof(entry.etag)},
                                true}))) {
        return 304;
    }
    return 200;
}

// RFC 9110 5.6.7: the date, patched lazily - an entry nobody asks for
// is never patched.
void Assets::head_patch_date(AssetEntry::Head &head, DateStamp when)
{
    if (head.unix_seconds == when.unix_seconds)
        return;
    std::memcpy(head.bytes.data() + head.date_offset, when.line, http::kDateLen);
    head.unix_seconds = when.unix_seconds;
}

// RFC 9112: the header section for a verdict this tier owns. Never body bytes.
void Assets::head_answer(const HeadAsk &head_ask, std::string &sink)
{
    const uint16_t status_code = head_ask.status_code;
    const ConnectionOption conn = head_ask.conn;
    // A refusal the caller has a page for cannot take the prebuilt head:
    // that one declares no body, and a page's length is not known until
    // there is a page. The fields are the same either way.
    if (head_ask.body_type != nullptr && (status_code == 405 || status_code == 406)) {
        sink.append(status_code == 405 ? kStatus405 : kStatus406).append("\r\nDate: ");
        sink.append(head_ask.date, http::kDateLen);
        sink.append("\r\n").append(kConnectionLine[conn]);
        sink.append(status_code == 405 ? kAllowField : kVaryField);
        sink.append("Content-Type: ").append(head_ask.body_type).append("\r\n");
        sink.append("Content-Length: ")
            .append(std::to_string(head_ask.body_len))
            .append("\r\n\r\n");
        return;
    }
    AssetEntry::Head *head;
    switch (status_code) {
        case 200:
            head = &head_ask.entry.head_200[conn];
            break;
        case 304:
            head = &head_ask.entry.head_304[conn];
            break;
        case 405:
            head = &s405_[conn];
            break;
        default:
            head = &s406_[conn];
            break;
    }
    head_patch_date(*head, {head_ask.date, head_ask.unix_seconds});
    sink.append(head->bytes);
}

// RFC 9110 14.4/15.3.7: the satisfied range and the complete length.
void Assets::answer_206_head(const HeadAsk &head_ask, std::string &sink)
{
    const AssetEntry &entry = head_ask.entry;
    const size_t first_byte_pos = head_ask.first_byte_pos;
    const size_t last_byte_pos = head_ask.last_byte_pos;
    sink.append("HTTP/1.1 206 Partial Content\r\nDate: ");
    sink.append(head_ask.date, http::kDateLen);
    sink.append("\r\n").append(kConnectionLine[head_ask.conn]);
    sink.append("Content-Type: ").append(entry.content_type).append("\r\n");
    if (entry.deflated) {
        sink.append("Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
    }
    sink.append("ETag: ").append(entry.etag, sizeof(entry.etag)).append("\r\n");
    sink.append("Accept-Ranges: bytes\r\n");
    sink.append("Content-Range: bytes ").append(std::to_string(first_byte_pos)).append("-");
    sink.append(std::to_string(last_byte_pos)).append("/").append(std::to_string(wire_len(entry)));
    sink.append("\r\nContent-Length: ").append(std::to_string(last_byte_pos - first_byte_pos + 1));
    sink.append("\r\n\r\n");
}

// RFC 9110 15.5.17: the unsatisfied form names the complete length.
void Assets::answer_416_head(const HeadAsk &head_ask, std::string &sink)
{
    const AssetEntry &entry = head_ask.entry;
    sink.append("HTTP/1.1 416 Range Not Satisfiable\r\nDate: ");
    sink.append(head_ask.date, http::kDateLen);
    sink.append("\r\n").append(kConnectionLine[head_ask.conn]);
    if (entry.deflated)
        sink.append(kVaryField);
    sink.append("Content-Range: bytes */").append(std::to_string(wire_len(entry))).append("\r\n");
    if (head_ask.body_type != nullptr) {
        sink.append("Content-Type: ").append(head_ask.body_type).append("\r\n");
    }
    sink.append("Content-Length: ").append(std::to_string(head_ask.body_len)).append("\r\n\r\n");
}

// RFC 1952 2.2: [off, off+n) of the wire body as pointers - the gzip
// header, the deflate stream where it lies in the mapping, the trailer.
// Up to three iovecs for one logical window, and only the middle one is
// the file: that is why this returns a count and not a pointer.
unsigned Assets::entry_wire_iov(const AssetEntry &entry, Window window, struct iovec *out_iov)
{
    size_t offset = window.off;
    size_t length = window.n;
    struct Seg {
        const char *part;
        size_t part_length;
    };
    Seg segs[3];
    size_t written = 0;
    if (entry.deflated) {
        segs[written++] = {reinterpret_cast<const char *>(entry.gzip_header),
                           sizeof(entry.gzip_header)};
        segs[written++] = {entry.file_data, entry.compressed_size};
        segs[written++] = {reinterpret_cast<const char *>(entry.gzip_trailer),
                           sizeof(entry.gzip_trailer)};
    } else {
        segs[written++] = {entry.file_data, entry.compressed_size};
    }
    unsigned used = 0;
    for (size_t i = 0; i < written && length != 0; i++) {
        if (offset >= segs[i].part_length) {
            offset -= segs[i].part_length;
            continue;
        }
        const size_t avail = segs[i].part_length - offset;
        const size_t take = avail < length ? avail : length;
        out_iov[used].iov_base = const_cast<char *>(segs[i].part + offset);
        out_iov[used].iov_len = take;
        used++;
        offset = 0;
        length -= take;
    }
    return used;
}

// RFC 1952: the same window, copied, for the paths that must own their bytes.
void Assets::entry_copy_wire(const AssetEntry &entry, Window window, std::string &sink)
{
    size_t offset = window.off;
    size_t length = window.n;
    struct Seg {
        const char *part;
        size_t part_length;
    };
    Seg segs[3];
    size_t written = 0;
    if (entry.deflated) {
        segs[written++] = {reinterpret_cast<const char *>(entry.gzip_header),
                           sizeof(entry.gzip_header)};
        segs[written++] = {entry.file_data, entry.compressed_size};
        segs[written++] = {reinterpret_cast<const char *>(entry.gzip_trailer),
                           sizeof(entry.gzip_trailer)};
    } else {
        segs[written++] = {entry.file_data, entry.compressed_size};
    }
    for (size_t i = 0; i < written && length != 0; i++) {
        if (offset >= segs[i].part_length) {
            offset -= segs[i].part_length;
            continue;
        }
        const size_t avail = segs[i].part_length - offset;
        const size_t take = avail < length ? avail : length;
        sink.append(segs[i].part + offset, take);
        offset = 0;
        length -= take;
    }
}
} // namespace webmachine
