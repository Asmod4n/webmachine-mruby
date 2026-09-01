// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <miniz.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace webmachine {
namespace {
// The order find_exact then searches in. A type, not a function pointer:
// the sort inlines the comparison the way it did the lambda this replaced.
struct ByFileName {
  bool operator()(const AssetEntry& a, const AssetEntry& b) const {
    return a.file_name < b.file_name;
  }
};

// The same order against a name that is not an entry yet.
struct NameBeforeKey {
  bool operator()(const AssetEntry& a, const std::pair<const char*, size_t>& key) const {
    const size_t n = a.file_name.size() < key.second ? a.file_name.size() : key.second;
    const int c = std::memcmp(a.file_name.data(), key.first, n);
    if (c != 0) return c < 0;
    return a.file_name.size() < key.second;
  }
};

// RFC 9110 5.6.7: the archive's mtime as Last-Modified; 0 serves none.
bool mtime_to_imf(time_t t, char out[http::kDateLen]) {
  if (t <= 0) return false;
  struct tm norm;
  if (gmtime_r(&t, &norm) == nullptr) return false;
  http::date_core(out, norm);
  return true;
}

// RFC 9110 8.8.3: the CRC-32 an ETag is spelled from.
void spell_hex8(char* out, uint32_t v) {
  static const char kHex[] = "0123456789abcdef";
  for (int i = 7; i >= 0; i--) {
    out[i] = kHex[v & 0xf];
    v >>= 4;
  }
}

// APPNOTE 4.5.2: an extra field block is a run of (id, size, payload),
// and a reader skips the ids it does not know. 0x574D is this tree's,
// written by the error_assets task: the finished <img> for the picture,
// so nothing here has a URL to join or a number to spell.
constexpr uint16_t kExtraImgTag = 0x574d;

struct Borrowed {
  const char* text = nullptr;
  size_t len = 0;
};

Borrowed img_tag_of(const unsigned char* extra, size_t len) {
  Borrowed b;
  size_t off = 0;
  while (off + 4 <= len) {
    const uint16_t id = MZ_READ_LE16(extra + off);
    const size_t size = MZ_READ_LE16(extra + off + 2);
    if (off + 4 + size > len) break;
    if (id == kExtraImgTag && size != 0) {
      b.text = reinterpret_cast<const char*>(extra + off + 4);
      b.len = size;
      break;
    }
    off += 4 + size;
  }
  return b;
}

// The parts of one prebuilt header section: the status line, the
// Connection field of the spelling being built, and the entry's own fields.
struct HeadParts {
  const char* status_line;
  const char* connection_line;
  const std::string& fields;
};

// RFC 9112: one prebuilt header section, Date placeholder at a kept offset.
void build_head(AssetEntry::Head& h, const HeadParts& p) {
  h.bytes.clear();
  h.bytes.append(p.status_line);
  h.bytes.append("\r\nDate: ");
  h.date_offset = h.bytes.size();
  h.bytes.append(http::kDatePlaceholder, http::kDateLen);
  h.bytes.append("\r\n").append(p.connection_line).append(p.fields).append("\r\n");
  h.unix_seconds = 0;
}

// RFC 9112 9.3: the same head in all three connection spellings.
// RFC 9110 15.5.6 and 12.5.3: what these two refusals carry besides the
// status - the same fields whether the answer has a page behind them or
// not, which is why they are named once and spelled twice.
constexpr char kStatus405[] = "HTTP/1.1 405 Method Not Allowed";
constexpr char kStatus406[] = "HTTP/1.1 406 Not Acceptable";
constexpr char kAllowField[] = "Allow: GET, HEAD\r\n";
constexpr char kVaryField[] = "Vary: Accept-Encoding\r\n";

void build_triple(AssetEntry::Head (&h)[3], const char* status_line, const std::string& fields) {
  for (uint8_t c = Assets::kNoConnectionField; c <= Assets::kConnClose; c++) {
    build_head(h[c], {status_line, Assets::kConnectionLine[c], fields});
  }
}
}

// The mapping is what serves, and it serves until the process ends.
Assets::~Assets() {
  if (map_addr_ != nullptr) ::munmap(const_cast<char*>(map_addr_), map_length_);
}

// ZIP (APPNOTE): archive in, entry table + prebuilt responses out. miniz
// parses; this reads only the 30-byte Local Header, to skip it.
bool Assets::open(const char* zip_path, const MimeDb& mime, char* err, size_t errlen) {
  const int fd = ::open(zip_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    std::snprintf(err, errlen, "%s: %s", zip_path, std::strerror(errno));
    return false;
  }
  struct stat st;
  if (::fstat(fd, &st) != 0 || st.st_size < 22) {
    ::close(fd);
    std::snprintf(err, errlen, "%s: not a ZIP (too small for an end record)", zip_path);
    return false;
  }
  map_length_ = static_cast<size_t>(st.st_size);
  void* m = ::mmap(nullptr, map_length_, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (m == MAP_FAILED) {
    map_length_ = 0;
    std::snprintf(err, errlen, "mmap %s: %s", zip_path, std::strerror(errno));
    return false;
  }
  map_addr_ = static_cast<const char*>(m);
  const unsigned char* base = reinterpret_cast<const unsigned char*>(map_addr_);

  mz_zip_archive za;
  std::memset(&za, 0, sizeof(za));
  if (!mz_zip_reader_init_mem(&za, map_addr_, map_length_, 0)) {
    std::snprintf(err, errlen, "%s: not a readable ZIP (%s)", zip_path,
                  mz_zip_get_error_string(mz_zip_get_last_error(&za)));
    return false;
  }
  struct Ender {
    mz_zip_archive* z;
    // miniz's reader is a setup tool and ends with this scope.
    ~Ender() { mz_zip_reader_end(z); }
  } ender{&za};

  const mz_uint n = mz_zip_reader_get_num_files(&za);
  if (n >= 0xffff) {
    std::snprintf(err, errlen, "%s: %u entries - Zip64 territory, excluded by design",
                  zip_path, n);
    return false;
  }
  entries_.reserve(n);

  for (mz_uint i = 0; i < n; i++) {
    mz_zip_archive_file_stat st;
    if (!mz_zip_reader_file_stat(&za, i, &st)) {
      std::snprintf(err, errlen, "%s: entry %u: %s", zip_path, i,
                    mz_zip_get_error_string(mz_zip_get_last_error(&za)));
      return false;
    }
    const size_t nlen = std::strlen(st.m_filename);

    if (st.m_is_directory) continue;
    if (st.m_is_encrypted) {
      std::snprintf(err, errlen, "%s: %s is encrypted - not supported", zip_path,
                    st.m_filename);
      return false;
    }
    if (st.m_method != 0 && st.m_method != MZ_DEFLATED) {
      std::snprintf(err, errlen,
                    "%s: %s uses method %u - only stored (0) and deflate (8) are served",
                    zip_path, st.m_filename, static_cast<unsigned>(st.m_method));
      return false;
    }
    if (st.m_comp_size > 0xffffffffULL || st.m_uncomp_size > 0xffffffffULL) {
      std::snprintf(err, errlen, "%s: %s is 4 GB or larger - Zip64, excluded by design",
                    zip_path, st.m_filename);
      return false;
    }

    const size_t lho = static_cast<size_t>(st.m_local_header_ofs);
    if (lho + 30 > map_length_ || MZ_READ_LE32(base + lho) != 0x04034b50) {
      std::snprintf(err, errlen, "%s: %s has a broken local header", zip_path,
                    st.m_filename);
      return false;
    }
    const size_t extra_off = lho + 30 + MZ_READ_LE16(base + lho + 26);
    const size_t extra_len = MZ_READ_LE16(base + lho + 28);
    const size_t data_off = extra_off + extra_len;
    const size_t comp = static_cast<size_t>(st.m_comp_size);
    if (data_off + comp > map_length_) {
      std::snprintf(err, errlen, "%s: %s data overruns the file", zip_path, st.m_filename);
      return false;
    }

    AssetEntry e;
    e.file_name.assign(st.m_filename, nlen);
    e.file_data = map_addr_ + data_off;
    e.compressed_size = comp;
    e.uncompressed_size = static_cast<size_t>(st.m_uncomp_size);
    e.crc32 = st.m_crc32;
    e.deflated = st.m_method == MZ_DEFLATED;
    e.last_modified_valid = mtime_to_imf(st.m_time, e.last_modified);
    e.etag[0] = '"';
    spell_hex8(e.etag + 1, st.m_crc32);
    e.etag[9] = '"';
    const Borrowed tag = img_tag_of(base + extra_off, extra_len);
    e.img_tag = tag.text;
    e.img_tag_len = tag.len;
    entries_.push_back(std::move(e));
  }

  std::stable_sort(entries_.begin(), entries_.end(), ByFileName());
  for (size_t i = 0; i + 1 < entries_.size();) {
    if (entries_[i].file_name == entries_[i + 1].file_name) entries_.erase(entries_.begin() + i);
    else i++;
  }

  for (AssetEntry& e : entries_) {
    e.content_type = http::with_charset(mime.type_of(e.file_name));
    std::string f;
    f.append("Content-Type: ").append(e.content_type).append("\r\n");
    if (e.deflated) {
      f.append("Content-Encoding: gzip\r\n");
      f.append("Vary: Accept-Encoding\r\n");
    }
    f.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
    if (e.last_modified_valid) {
      f.append("Last-Modified: ").append(e.last_modified, sizeof(e.last_modified)).append("\r\n");
    }
    f.append("Accept-Ranges: bytes\r\n");
    const size_t clen = e.deflated ? e.compressed_size + 18 : e.compressed_size;
    f.append("Content-Length: ").append(std::to_string(clen)).append("\r\n");
    build_triple(e.head_200, "HTTP/1.1 200 OK", f);

    std::string f304;
    f304.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
    if (e.deflated) f304.append("Vary: Accept-Encoding\r\n");
    build_triple(e.head_304, "HTTP/1.1 304 Not Modified", f304);

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

  build_triple(s405_, kStatus405, std::string(kAllowField) + "Content-Length: 0\r\n");
  build_triple(s406_, kStatus406, std::string(kVaryField) + "Content-Length: 0\r\n");
  return true;
}

// One entry, by name, exact bytes.
const AssetEntry* Assets::find_exact(const char* name, size_t len) const {
  const auto it = std::lower_bound(entries_.begin(), entries_.end(),
                                   std::pair<const char*, size_t>(name, len), NameBeforeKey());
  if (it == entries_.end() || it->file_name.size() != len ||
      std::memcmp(it->file_name.data(), name, len) != 0) {
    return nullptr;
  }
  return &*it;
}

// RFC 9110 4.2.1: the target names a table row, byte for byte - or, for a
// path that names a directory (root "/", or anything ending "/"), that
// directory's own index.html, the near-universal default document. A pack
// with no index.html at that path answers 404 exactly as before; nothing
// here invents a directory listing.
AssetEntry* Assets::find(const char* path, size_t len) {
  if (len == 0 || path[0] != '/') return nullptr;
  path++;
  len--;
  for (size_t i = 0; i < len; i++) {
    if (path[i] == '?') {
      len = i;
      break;
    }
  }
  if (len == 0 || path[len - 1] == '/') {
    static constexpr char kIndex[] = "index.html";
    static constexpr size_t kIndexLen = sizeof(kIndex) - 1;
    char buf[kMaxHead];
    if (len + kIndexLen > sizeof(buf)) return nullptr;
    if (len != 0) std::memcpy(buf, path, len);
    std::memcpy(buf + len, kIndex, kIndexLen);
    return const_cast<AssetEntry*>(find_exact(buf, len + kIndexLen));
  }
  return const_cast<AssetEntry*>(find_exact(path, len));
}

// RFC 9110: the asset tier's whole decision, in the graph's own order -
// 405/501, 406 (12.5.3+15.5.7), 412 (13.1.1), 304 (13.1.2), else 200.
uint16_t Assets::verdict(const AssetEntry& e, const AssetRequest& r) const {
  const flow::ReqFacts& f = r.facts;
  const http::ReqValues& vals = r.vals;
  switch (f.method) {
    case flow::Method::kGet:
    case flow::Method::kHead:
      break;
    case flow::Method::kOther:
      return 501;
    default:
      return 405;
  }
  if (e.deflated && f.has_accept_encoding &&
      !http::gzip_acceptable(vals.accept_encoding, vals.accept_encoding_len)) {
    return 406;
  }
  if (f.has_if_match && !f.if_match_star &&
      !http::etag_list_match(vals.if_match, vals.if_match_len, e.etag, sizeof(e.etag),
                             false)) {
    return 412;
  }
  if (f.has_if_none_match &&
      (f.if_none_match_star ||
       http::etag_list_match(vals.if_none_match, vals.if_none_match_len, e.etag,
                             sizeof(e.etag), true))) {
    return 304;
  }
  return 200;
}

// RFC 9110 5.6.7: the date, patched lazily - an entry nobody asks for
// is never patched.
void Assets::patch_date(AssetEntry::Head& h, const char* date, time_t unix_seconds) {
  if (h.unix_seconds == unix_seconds) return;
  std::memcpy(h.bytes.data() + h.date_offset, date, http::kDateLen);
  h.unix_seconds = unix_seconds;
}

// RFC 9112: the header section for a verdict this tier owns. Never body bytes.
void Assets::answer_head(const HeadAsk& ask, std::string& sink) {
  const uint16_t status_code = ask.status_code;
  const ConnectionOption conn = ask.conn;
  // A refusal the caller has a page for cannot take the prebuilt head:
  // that one declares no body, and a page's length is not known until
  // there is a page. The fields are the same either way.
  if (ask.body_type != nullptr && (status_code == 405 || status_code == 406)) {
    sink.append(status_code == 405 ? kStatus405 : kStatus406).append("\r\nDate: ");
    sink.append(ask.date, http::kDateLen);
    sink.append("\r\n").append(kConnectionLine[conn]);
    sink.append(status_code == 405 ? kAllowField : kVaryField);
    sink.append("Content-Type: ").append(ask.body_type).append("\r\n");
    sink.append("Content-Length: ").append(std::to_string(ask.body_len)).append("\r\n\r\n");
    return;
  }
  AssetEntry::Head* h;
  switch (status_code) {
    case 200: h = &ask.entry.head_200[conn]; break;
    case 304: h = &ask.entry.head_304[conn]; break;
    case 405: h = &s405_[conn]; break;
    default: h = &s406_[conn]; break;
  }
  patch_date(*h, ask.date, ask.unix_seconds);
  sink.append(h->bytes);
}

// RFC 9110 14.4/15.3.7: the satisfied range and the complete length.
void Assets::answer_206_head(const HeadAsk& ask, std::string& sink) {
  const AssetEntry& e = ask.entry;
  const size_t first_byte_pos = ask.first_byte_pos;
  const size_t last_byte_pos = ask.last_byte_pos;
  sink.append("HTTP/1.1 206 Partial Content\r\nDate: ");
  sink.append(ask.date, http::kDateLen);
  sink.append("\r\n").append(kConnectionLine[ask.conn]);
  sink.append("Content-Type: ").append(e.content_type).append("\r\n");
  if (e.deflated) {
    sink.append("Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
  }
  sink.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
  sink.append("Accept-Ranges: bytes\r\n");
  sink.append("Content-Range: bytes ").append(std::to_string(first_byte_pos)).append("-");
  sink.append(std::to_string(last_byte_pos)).append("/").append(std::to_string(wire_len(e)));
  sink.append("\r\nContent-Length: ")
      .append(std::to_string(last_byte_pos - first_byte_pos + 1));
  sink.append("\r\n\r\n");
}

// RFC 9110 15.5.17: the unsatisfied form names the complete length.
void Assets::answer_416_head(const HeadAsk& ask, std::string& sink) {
  const AssetEntry& e = ask.entry;
  sink.append("HTTP/1.1 416 Range Not Satisfiable\r\nDate: ");
  sink.append(ask.date, http::kDateLen);
  sink.append("\r\n").append(kConnectionLine[ask.conn]);
  if (e.deflated) sink.append(kVaryField);
  sink.append("Content-Range: bytes */").append(std::to_string(wire_len(e))).append("\r\n");
  if (ask.body_type != nullptr) {
    sink.append("Content-Type: ").append(ask.body_type).append("\r\n");
  }
  sink.append("Content-Length: ").append(std::to_string(ask.body_len)).append("\r\n\r\n");
}

// RFC 1952 2.2: [off, off+n) of the wire body as POINTERS - the gzip
// header, the deflate stream where it lies in the mapping, the trailer.
// Up to THREE iovecs for ONE logical window, and only the middle one is
// the file: that is why this returns a count and not a pointer.
unsigned Assets::wire_iov(const AssetEntry& e, size_t off, size_t n, struct iovec* iov) {
  struct Seg {
    const char* p;
    size_t len;
  };
  Seg segs[3];
  size_t ns = 0;
  if (e.deflated) {
    segs[ns++] = {reinterpret_cast<const char*>(e.gzip_header), sizeof(e.gzip_header)};
    segs[ns++] = {e.file_data, e.compressed_size};
    segs[ns++] = {reinterpret_cast<const char*>(e.gzip_trailer), sizeof(e.gzip_trailer)};
  } else {
    segs[ns++] = {e.file_data, e.compressed_size};
  }
  unsigned out = 0;
  for (size_t i = 0; i < ns && n != 0; i++) {
    if (off >= segs[i].len) {
      off -= segs[i].len;
      continue;
    }
    const size_t avail = segs[i].len - off;
    const size_t take = avail < n ? avail : n;
    iov[out].iov_base = const_cast<char*>(segs[i].p + off);
    iov[out].iov_len = take;
    out++;
    off = 0;
    n -= take;
  }
  return out;
}

// RFC 1952: the same window, copied, for the paths that must own their bytes.
void Assets::copy_wire(const AssetEntry& e, size_t off, size_t n, std::string& sink) {
  struct Seg {
    const char* p;
    size_t len;
  };
  Seg segs[3];
  size_t ns = 0;
  if (e.deflated) {
    segs[ns++] = {reinterpret_cast<const char*>(e.gzip_header), sizeof(e.gzip_header)};
    segs[ns++] = {e.file_data, e.compressed_size};
    segs[ns++] = {reinterpret_cast<const char*>(e.gzip_trailer), sizeof(e.gzip_trailer)};
  } else {
    segs[ns++] = {e.file_data, e.compressed_size};
  }
  for (size_t i = 0; i < ns && n != 0; i++) {
    if (off >= segs[i].len) {
      off -= segs[i].len;
      continue;
    }
    const size_t avail = segs[i].len - off;
    const size_t take = avail < n ? avail : n;
    sink.append(segs[i].p + off, take);
    off = 0;
    n -= take;
  }
}
}
