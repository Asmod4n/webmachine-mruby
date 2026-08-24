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

// RFC 9112: one prebuilt header section, Date placeholder at a kept offset.
void build_head(AssetEntry::Resp& r, const char* status_line, const char* conn,
                const std::string& fields) {
  r.bytes.clear();
  r.bytes.append(status_line);
  r.bytes.append("\r\nDate: ");
  r.date_off = r.bytes.size();
  r.bytes.append(http::kDatePlaceholder, http::kDateLen);
  r.bytes.append("\r\n").append(conn).append(fields).append("\r\n");
  r.sec = 0;
}

// RFC 9112 9.3: the same head in all three connection spellings.
void build_triple(AssetEntry::Resp (&v)[3], const char* status_line, const std::string& fields) {
  build_head(v[Assets::kPlain], status_line, Assets::kConn[Assets::kPlain], fields);
  build_head(v[Assets::kKeep], status_line, Assets::kConn[Assets::kKeep], fields);
  build_head(v[Assets::kClose], status_line, Assets::kConn[Assets::kClose], fields);
}
}

// The mapping is what serves, and it serves until the process ends.
Assets::~Assets() {
  if (map_ != nullptr) ::munmap(const_cast<char*>(map_), map_len_);
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
  map_len_ = static_cast<size_t>(st.st_size);
  void* m = ::mmap(nullptr, map_len_, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (m == MAP_FAILED) {
    map_len_ = 0;
    std::snprintf(err, errlen, "mmap %s: %s", zip_path, std::strerror(errno));
    return false;
  }
  map_ = static_cast<const char*>(m);
  const unsigned char* base = reinterpret_cast<const unsigned char*>(map_);

  mz_zip_archive za;
  std::memset(&za, 0, sizeof(za));
  if (!mz_zip_reader_init_mem(&za, map_, map_len_, 0)) {
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
    if (lho + 30 > map_len_ || MZ_READ_LE32(base + lho) != 0x04034b50) {
      std::snprintf(err, errlen, "%s: %s has a broken local header", zip_path,
                    st.m_filename);
      return false;
    }
    const size_t data_off = lho + 30 + MZ_READ_LE16(base + lho + 26) + MZ_READ_LE16(base + lho + 28);
    const size_t comp = static_cast<size_t>(st.m_comp_size);
    if (data_off + comp > map_len_) {
      std::snprintf(err, errlen, "%s: %s data overruns the file", zip_path, st.m_filename);
      return false;
    }

    AssetEntry e;
    e.name.assign(st.m_filename, nlen);
    e.data = map_ + data_off;
    e.comp_size = comp;
    e.uncomp_size = static_cast<size_t>(st.m_uncomp_size);
    e.crc = st.m_crc32;
    e.deflated = st.m_method == MZ_DEFLATED;
    e.lm_valid = mtime_to_imf(st.m_time, e.lm);
    e.etag[0] = '"';
    spell_hex8(e.etag + 1, st.m_crc32);
    e.etag[9] = '"';
    entries_.push_back(std::move(e));
  }

  std::stable_sort(entries_.begin(), entries_.end(),
                   [](const AssetEntry& a, const AssetEntry& b) { return a.name < b.name; });
  for (size_t i = 0; i + 1 < entries_.size();) {
    if (entries_[i].name == entries_[i + 1].name) entries_.erase(entries_.begin() + i);
    else i++;
  }

  for (AssetEntry& e : entries_) {
    e.ctype = http::with_charset(mime.type_of(e.name));
    std::string f;
    f.append("Content-Type: ").append(e.ctype).append("\r\n");
    if (e.deflated) {
      f.append("Content-Encoding: gzip\r\n");
      f.append("Vary: Accept-Encoding\r\n");
    }
    f.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
    if (e.lm_valid) f.append("Last-Modified: ").append(e.lm, sizeof(e.lm)).append("\r\n");
    f.append("Accept-Ranges: bytes\r\n");
    const size_t clen = e.deflated ? e.comp_size + 18 : e.comp_size;
    f.append("Content-Length: ").append(std::to_string(clen)).append("\r\n");
    build_triple(e.h200, "HTTP/1.1 200 OK", f);

    std::string f304;
    f304.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
    if (e.deflated) f304.append("Vary: Accept-Encoding\r\n");
    build_triple(e.h304, "HTTP/1.1 304 Not Modified", f304);

    if (e.deflated) {
      static const unsigned char kGzHdr[10] = {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff};
      std::memcpy(e.gz_hdr, kGzHdr, sizeof(kGzHdr));
      e.gz_trailer[0] = static_cast<unsigned char>(e.crc);
      e.gz_trailer[1] = static_cast<unsigned char>(e.crc >> 8);
      e.gz_trailer[2] = static_cast<unsigned char>(e.crc >> 16);
      e.gz_trailer[3] = static_cast<unsigned char>(e.crc >> 24);
      e.gz_trailer[4] = static_cast<unsigned char>(e.uncomp_size);
      e.gz_trailer[5] = static_cast<unsigned char>(e.uncomp_size >> 8);
      e.gz_trailer[6] = static_cast<unsigned char>(e.uncomp_size >> 16);
      e.gz_trailer[7] = static_cast<unsigned char>(e.uncomp_size >> 24);
    }
  }

  build_triple(s405_, "HTTP/1.1 405 Method Not Allowed",
               "Allow: GET, HEAD\r\nContent-Length: 0\r\n");
  build_triple(s406_, "HTTP/1.1 406 Not Acceptable",
               "Vary: Accept-Encoding\r\nContent-Length: 0\r\n");
  return true;
}

// RFC 9110 4.2.1: the target names a table row, byte for byte, or nothing.
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
  if (len == 0) return nullptr;
  const auto it = std::lower_bound(
      entries_.begin(), entries_.end(), std::pair<const char*, size_t>(path, len),
      [](const AssetEntry& a, const std::pair<const char*, size_t>& key) {
        const int c = std::memcmp(a.name.data(), key.first,
                                  a.name.size() < key.second ? a.name.size() : key.second);
        if (c != 0) return c < 0;
        return a.name.size() < key.second;
      });
  if (it == entries_.end() || it->name.size() != len ||
      std::memcmp(it->name.data(), path, len) != 0) {
    return nullptr;
  }
  return &*it;
}

// RFC 9110: the asset tier's whole decision, in the graph's own order -
// 405/501, 406 (12.5.3+15.5.7), 412 (13.1.1), 304 (13.1.2), else 200.
uint16_t Assets::verdict(const AssetEntry& e, flow::Method m, const flow::ReqFacts& f,
                         const http::ReqValues& vals) const {
  switch (m) {
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
      (f.inm_star || http::etag_list_match(vals.if_none_match, vals.if_none_match_len, e.etag,
                                           sizeof(e.etag), true))) {
    return 304;
  }
  return 200;
}

// RFC 9110 5.6.7: the date, patched lazily - an entry nobody asks for
// is never patched.
void Assets::patch_date(AssetEntry::Resp& r, const char* date, time_t sec) {
  if (r.sec == sec) return;
  std::memcpy(r.bytes.data() + r.date_off, date, http::kDateLen);
  r.sec = sec;
}

// RFC 9112: the header section for a verdict this tier owns. Never body bytes.
void Assets::answer_head(AssetEntry& e, uint16_t status, Variant v, const char* date,
                         time_t sec, std::string& sink) {
  AssetEntry::Resp* r;
  switch (status) {
    case 200: r = &e.h200[v]; break;
    case 304: r = &e.h304[v]; break;
    case 405: r = &s405_[v]; break;
    default: r = &s406_[v]; break;
  }
  patch_date(*r, date, sec);
  sink.append(r->bytes);
}

namespace {
}

// RFC 9110 14.4/15.3.7: the satisfied range and the complete length.
void Assets::answer_206_head(const AssetEntry& e, Variant v, size_t first, size_t last,
                             const char* date, std::string& sink) {
  sink.append("HTTP/1.1 206 Partial Content\r\nDate: ");
  sink.append(date, http::kDateLen);
  sink.append("\r\n").append(kConn[v]);
  sink.append("Content-Type: ").append(e.ctype).append("\r\n");
  if (e.deflated) {
    sink.append("Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
  }
  sink.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
  sink.append("Accept-Ranges: bytes\r\n");
  sink.append("Content-Range: bytes ").append(std::to_string(first)).append("-");
  sink.append(std::to_string(last)).append("/").append(std::to_string(wire_len(e)));
  sink.append("\r\nContent-Length: ").append(std::to_string(last - first + 1));
  sink.append("\r\n\r\n");
}

// RFC 9110 15.5.17: the unsatisfied form names the complete length.
void Assets::answer_416_head(const AssetEntry& e, Variant v, const char* date,
                             std::string& sink) {
  sink.append("HTTP/1.1 416 Range Not Satisfiable\r\nDate: ");
  sink.append(date, http::kDateLen);
  sink.append("\r\n").append(kConn[v]);
  if (e.deflated) sink.append("Vary: Accept-Encoding\r\n");
  sink.append("Content-Range: bytes */").append(std::to_string(wire_len(e)));
  sink.append("\r\nContent-Length: 0\r\n\r\n");
}

// RFC 1952: [off, off+n) of the wire body as POINTERS - gzip header,
// the deflate stream where it lies in the mapping, the trailer.
unsigned Assets::wire_iov(const AssetEntry& e, size_t off, size_t n, struct iovec* iov) {
  struct Seg {
    const char* p;
    size_t len;
  };
  Seg segs[3];
  size_t ns = 0;
  if (e.deflated) {
    segs[ns++] = {reinterpret_cast<const char*>(e.gz_hdr), sizeof(e.gz_hdr)};
    segs[ns++] = {e.data, e.comp_size};
    segs[ns++] = {reinterpret_cast<const char*>(e.gz_trailer), sizeof(e.gz_trailer)};
  } else {
    segs[ns++] = {e.data, e.comp_size};
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
    segs[ns++] = {reinterpret_cast<const char*>(e.gz_hdr), sizeof(e.gz_hdr)};
    segs[ns++] = {e.data, e.comp_size};
    segs[ns++] = {reinterpret_cast<const char*>(e.gz_trailer), sizeof(e.gz_trailer)};
  } else {
    segs[ns++] = {e.data, e.comp_size};
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
