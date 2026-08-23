// The ZIP side of the asset tier (#170, corrected by #177): archive
// in, entry table + prebuilt responses out. Runs ONCE at setup -
// classic open/mmap is fine here (ring.hpp exempts mmap by name:
// memory, not IO). The fd does not outlive setup: the mapping is what
// serves, and it keeps serving - a request's bytes are an iovec into
// these pages, never a copy.
//
// THE ARCHIVE IS PARSED BY miniz, NOT BY THIS FILE (Nutzer-Entscheid:
// ".zip ist ne riesen Angriffsflaeche, da was selbst zu rollen schreit
// danach CVEs zu wollen"). What used to live here was an end record
// scanned backwards over 64 KiB, 46-byte central directory rows with
// four variable-length fields each, Zip64 escapes, an encryption flag,
// and a bounds check against the mapping behind every one of them -
// 137 instrumented edges of hand-written foreign-format parsing, which
// is the shape every ZIP CVE has ever had.
//
// WHY miniz AND NOT libzip, which the standing rule would prefer (a
// stable ABI that every distribution carries): libzip cannot answer
// the question this tier asks. It hands over BYTES - zip_fopen_index
// plus zip_fread - and has no public API for an entry's POSITION;
// zip_source_seek_compute_offset is a helper for source
// implementations, not that. Taking it would mean copying every served
// byte into an arena at setup and losing the mapping: file-backed
// pages the kernel faults in on demand and can evict would become
// anonymous RSS that must all stay resident. The delivery model (#155,
// #168 - an iovec into the mapping, sendmsg, no copy) is not something
// to trade for a packaging preference.
//
// miniz answers it: mz_zip_reader_init_mem parses OUR mapping with no
// IO at all (MINIZ_NO_STDIO is a first-class build switch, not a
// workaround), and mz_zip_archive_file_stat carries m_local_header_ofs
// - a position - next to the metadata HTTP needs: m_comp_size,
// m_uncomp_size, m_crc32, m_method, m_time as a time_t (so the DOS
// date arithmetic goes with the parser), m_is_directory,
// m_is_encrypted, m_is_supported.
//
// WHAT THIS FILE STILL READS OF THE FORMAT, and it is the whole of it:
// the 30-byte Local Header, to skip it. Its name and extra lengths may
// differ from the directory's, so they must be read locally - a
// signature check and two uint16 at +26 and +28. Five lines against
// the directory walk that is gone.
#include "assets.hpp"

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

uint16_t rd16(const unsigned char* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t rd32(const unsigned char* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// Content-Type from the extension, decided at setup. Unknown speaks
// octet-stream (RFC 9110 §8.3: no type claim is worse than a generic
// one only when it lies; octet-stream never does).
const char* ctype_of(const std::string& name) {
  const size_t dot = name.rfind('.');
  if (dot == std::string::npos) return "application/octet-stream";
  const char* e = name.c_str() + dot + 1;
  const size_t n = name.size() - dot - 1;
  const auto is = [&](const char* lit) { return std::strlen(lit) == n && std::memcmp(e, lit, n) == 0; };
  if (is("html") || is("htm")) return "text/html";
  if (is("css")) return "text/css";
  if (is("js") || is("mjs")) return "text/javascript";
  if (is("json") || is("map")) return "application/json";
  if (is("svg")) return "image/svg+xml";
  if (is("png")) return "image/png";
  if (is("jpg") || is("jpeg")) return "image/jpeg";
  if (is("gif")) return "image/gif";
  if (is("webp")) return "image/webp";
  if (is("avif")) return "image/avif";
  if (is("ico")) return "image/x-icon";
  if (is("woff2")) return "font/woff2";
  if (is("woff")) return "font/woff";
  if (is("txt")) return "text/plain";
  if (is("xml")) return "application/xml";
  if (is("pdf")) return "application/pdf";
  if (is("wasm")) return "application/wasm";
  if (is("mp4")) return "video/mp4";
  if (is("webm")) return "video/webm";
  return "application/octet-stream";
}

// The archive's mtime to IMF-fixdate. miniz has already read whichever
// of the DOS date/time fields (appnote 4.4.6) or the extended-timestamp
// extra field the archive carried, and hands over a time_t - so the bit
// arithmetic that used to live here went with the parser. The zone is
// unknowable for a DOS date (they are "local" with no zone recorded);
// read as UTC, which every tool in the chain also pretends. Zero means
// "no date recorded" and serves no Last-Modified.
bool mtime_to_imf(time_t t, char out[http::kDateLen]) {
  if (t <= 0) return false;
  struct tm norm;
  if (gmtime_r(&t, &norm) == nullptr) return false;
  http::date_core(out, norm);
  return true;
}

void spell_hex8(char* out, uint32_t v) {
  static const char kHex[] = "0123456789abcdef";
  for (int i = 7; i >= 0; i--) {
    out[i] = kHex[v & 0xf];
    v >>= 4;
  }
}

// One h1 header section: status line, Date placeholder (offset kept),
// the connection spelling, the entry's fields, the blank line.
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

void build_triple(AssetEntry::Resp (&v)[3], const char* status_line, const std::string& fields) {
  build_head(v[Assets::kPlain], status_line, "", fields);
  build_head(v[Assets::kKeep], status_line, "Connection: keep-alive\r\n", fields);
  build_head(v[Assets::kClose], status_line, "Connection: close\r\n", fields);
}

}  // namespace

Assets::~Assets() {
  if (map_ != nullptr) ::munmap(const_cast<char*>(map_), map_len_);
}

bool Assets::open(const char* zip_path, char* err, size_t errlen) {
  // The fd is a SETUP tool, closed before this function returns: the
  // mapping keeps the pages alive by itself, and nothing past setup
  // ever reads the archive through a descriptor. One fd fewer against
  // ring.hpp's kFdReserve, and one fewer thing to own.
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

  // miniz over OUR mapping: no fd, no read, no seek - it walks the
  // Central Directory in the pages already faulted in.
  mz_zip_archive za;
  std::memset(&za, 0, sizeof(za));
  if (!mz_zip_reader_init_mem(&za, map_, map_len_, 0)) {
    std::snprintf(err, errlen, "%s: not a readable ZIP (%s)", zip_path,
                  mz_zip_get_error_string(mz_zip_get_last_error(&za)));
    return false;
  }
  struct Ender {
    mz_zip_archive* z;
    ~Ender() { mz_zip_reader_end(z); }
  } ender{&za};

  const mz_uint n = mz_zip_reader_get_num_files(&za);
  // #170's Explorer requirement as a number: under 65535 entries and
  // under 4 GB, so no Zip64 record is needed anywhere. Refused by name
  // rather than half-supported.
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

    // Directory rows carry no bytes to serve.
    if (st.m_is_directory) continue;
    // Both refusals are miniz's own findings, restated in this tier's
    // words - m_is_supported covers the methods and the patch-file bit
    // it will not read.
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

    // THE ONLY ZIP BYTES THIS FILE STILL READS. miniz gives the Local
    // Header's offset, not the data's, and the header's own name and
    // extra lengths may differ from the directory's - so they are read
    // where they are, and the result is bounds-checked against the
    // mapping like everything that indexes into it.
    const size_t lho = static_cast<size_t>(st.m_local_header_ofs);
    if (lho + 30 > map_len_ || rd32(base + lho) != 0x04034b50) {
      std::snprintf(err, errlen, "%s: %s has a broken local header", zip_path,
                    st.m_filename);
      return false;
    }
    const size_t data_off = lho + 30 + rd16(base + lho + 26) + rd16(base + lho + 28);
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

  // Sorted for the binary search; a duplicated name keeps its LAST
  // directory row - the row a rewriting tool appended most recently.
  std::stable_sort(entries_.begin(), entries_.end(),
                   [](const AssetEntry& a, const AssetEntry& b) { return a.name < b.name; });
  for (size_t i = 0; i + 1 < entries_.size();) {
    if (entries_[i].name == entries_[i + 1].name) entries_.erase(entries_.begin() + i);
    else i++;
  }

  // Prebuild what every request would otherwise redo.
  for (AssetEntry& e : entries_) {
    e.ctype = http::with_charset(ctype_of(e.name));
    std::string f;
    f.append("Content-Type: ").append(e.ctype).append("\r\n");
    if (e.deflated) {
      f.append("Content-Encoding: gzip\r\n");
      // A cache must not hand the gzip answer to a client this tier
      // would refuse with 406 (RFC 9110 §12.5.5).
      f.append("Vary: Accept-Encoding\r\n");
    }
    f.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
    if (e.lm_valid) f.append("Last-Modified: ").append(e.lm, sizeof(e.lm)).append("\r\n");
    // Advertised because it is true (#148, RFC 9110 14.3) - both
    // methods range over the wire body through the same copy_wire.
    f.append("Accept-Ranges: bytes\r\n");
    // gzip framing costs exactly 18 bytes: 10 header + 8 trailer.
    const size_t clen = e.deflated ? e.comp_size + 18 : e.comp_size;
    f.append("Content-Length: ").append(std::to_string(clen)).append("\r\n");
    build_triple(e.h200, "HTTP/1.1 200 OK", f);

    // 304 repeats what a cache updates by (RFC 9110 §15.4.5): ETag,
    // and Vary where the 200 carried it. Bodyless by definition.
    std::string f304;
    f304.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
    if (e.deflated) f304.append("Vary: Accept-Encoding\r\n");
    build_triple(e.h304, "HTTP/1.1 304 Not Modified", f304);

    if (e.deflated) {
      // RFC 1952: magic, CM=8, FLG=0, MTIME=0 (unknown), XFL=0,
      // OS=0xff (unknown) - the exact values that keep this constant.
      static const unsigned char kGzHdr[10] = {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff};
      std::memcpy(e.gz_hdr, kGzHdr, sizeof(kGzHdr));
      // CRC-32 and ISIZE, little-endian (RFC 1952 2.3) - both straight
      // out of the Central Directory. No runtime compression, no
      // decompression, ever.
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

AssetEntry* Assets::find(const char* path, size_t len) {
  if (len == 0 || path[0] != '/') return nullptr;
  path++;
  len--;
  for (size_t i = 0; i < len; i++) {
    if (path[i] == '?') {  // the query never names an entry
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
                             /*weak=*/false)) {
    return 412;
  }
  if (f.has_if_none_match &&
      (f.inm_star || http::etag_list_match(vals.if_none_match, vals.if_none_match_len, e.etag,
                                           sizeof(e.etag), /*weak=*/true))) {
    return 304;
  }
  return 200;
}

void Assets::patch_date(AssetEntry::Resp& r, const char* date, time_t sec) {
  if (r.sec == sec) return;
  std::memcpy(r.bytes.data() + r.date_off, date, http::kDateLen);
  r.sec = sec;
}

void Assets::answer_head(AssetEntry& e, uint16_t status, Variant v, const char* date,
                         time_t sec, std::string& sink) {
  AssetEntry::Resp* r;
  switch (status) {
    case 200: r = &e.h200[v]; break;
    case 304: r = &e.h304[v]; break;
    case 405: r = &s405_[v]; break;
    default: r = &s406_[v]; break;  // verdict() hands this tier nothing else
  }
  patch_date(*r, date, sec);
  sink.append(r->bytes);
}

namespace {

// The connection spelling for a per-request head (no placeholder, the
// date goes in directly - nothing patches these later).
const char* conn_of(Assets::Variant v) {
  switch (v) {
    case Assets::kKeep: return "Connection: keep-alive\r\n";
    case Assets::kClose: return "Connection: close\r\n";
    default: return "";
  }
}

}  // namespace

void Assets::answer_206_head(const AssetEntry& e, Variant v, size_t first, size_t last,
                             const char* date, std::string& sink) {
  sink.append("HTTP/1.1 206 Partial Content\r\nDate: ");
  sink.append(date, http::kDateLen);
  sink.append("\r\n").append(conn_of(v));
  sink.append("Content-Type: ").append(e.ctype).append("\r\n");
  if (e.deflated) {
    sink.append("Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
  }
  sink.append("ETag: ").append(e.etag, sizeof(e.etag)).append("\r\n");
  sink.append("Accept-Ranges: bytes\r\n");
  // RFC 9110 14.4/15.3.7: the satisfied range and the complete length,
  // both counting the wire body's octets.
  sink.append("Content-Range: bytes ").append(std::to_string(first)).append("-");
  sink.append(std::to_string(last)).append("/").append(std::to_string(wire_len(e)));
  sink.append("\r\nContent-Length: ").append(std::to_string(last - first + 1));
  sink.append("\r\n\r\n");
}

void Assets::answer_416_head(const AssetEntry& e, Variant v, const char* date,
                             std::string& sink) {
  sink.append("HTTP/1.1 416 Range Not Satisfiable\r\nDate: ");
  sink.append(date, http::kDateLen);
  sink.append("\r\n").append(conn_of(v));
  if (e.deflated) sink.append("Vary: Accept-Encoding\r\n");
  // 15.5.17: the unsatisfied-range form names the complete length.
  sink.append("Content-Range: bytes */").append(std::to_string(wire_len(e)));
  sink.append("\r\nContent-Length: 0\r\n\r\n");
}

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
    // The pointer goes out as it lies - into the mapping for the
    // deflate stream, into the entry for the 18 framing bytes. Both
    // outlive any send: the mapping is process-lifetime, the entry is
    // in the table built at add_route.
    iov[out].iov_base = const_cast<char*>(segs[i].p + off);
    iov[out].iov_len = take;
    out++;
    off = 0;
    n -= take;
  }
  return out;
}

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

}  // namespace webmachine
