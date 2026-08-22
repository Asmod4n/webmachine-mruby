// The ZIP side of the asset tier (#170): Central Directory in, entry
// table + prebuilt responses out. Runs ONCE at setup - classic
// open/mmap is fine here (ring.hpp exempts mmap by name: memory, not
// IO; the fd stays open for the splice path, #168).
#include "assets.hpp"

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

// DOS date/time (ZIP appnote 4.4.6) to IMF-fixdate. The zone is
// unknowable (DOS times are "local" with no zone recorded); read as
// UTC, which every tool in the chain also pretends.
bool dos_to_imf(uint16_t ddate, uint16_t dtime, char out[http::kDateLen]) {
  struct tm tm {};
  const int day = ddate & 0x1f;
  const int mon = (ddate >> 5) & 0x0f;
  const int year = ((ddate >> 9) & 0x7f) + 1980;
  if (day < 1 || mon < 1 || mon > 12) return false;  // 0 = "no date recorded"
  tm.tm_mday = day;
  tm.tm_mon = mon - 1;
  tm.tm_year = year - 1900;
  tm.tm_hour = (dtime >> 11) & 0x1f;
  tm.tm_min = (dtime >> 5) & 0x3f;
  tm.tm_sec = (dtime & 0x1f) * 2;
  const time_t t = timegm(&tm);
  if (t == static_cast<time_t>(-1)) return false;
  struct tm norm;
  gmtime_r(&t, &norm);  // fills tm_wday, normalizes a 31st of a short month
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
  if (fd_ >= 0) ::close(fd_);
}

bool Assets::open(const char* zip_path, char* err, size_t errlen) {
  fd_ = ::open(zip_path, O_RDONLY | O_CLOEXEC);
  if (fd_ < 0) {
    std::snprintf(err, errlen, "%s: %s", zip_path, std::strerror(errno));
    return false;
  }
  struct stat st;
  if (::fstat(fd_, &st) != 0 || st.st_size < 22) {
    std::snprintf(err, errlen, "%s: not a ZIP (too small for an end record)", zip_path);
    return false;
  }
  map_len_ = static_cast<size_t>(st.st_size);
  void* m = ::mmap(nullptr, map_len_, PROT_READ, MAP_PRIVATE, fd_, 0);
  if (m == MAP_FAILED) {
    map_len_ = 0;
    std::snprintf(err, errlen, "mmap %s: %s", zip_path, std::strerror(errno));
    return false;
  }
  map_ = static_cast<const char*>(m);
  const unsigned char* base = reinterpret_cast<const unsigned char*>(map_);

  // End of Central Directory: last 0x06054b50 within the final 64K+22
  // (the trailing comment's maximum reach, appnote 4.3.16).
  size_t eocd = SIZE_MAX;
  {
    const size_t lo = map_len_ > 65557 ? map_len_ - 65557 : 0;
    for (size_t i = map_len_ - 22 + 1; i-- > lo;) {
      if (rd32(base + i) == 0x06054b50) {
        eocd = i;
        break;
      }
    }
  }
  if (eocd == SIZE_MAX) {
    std::snprintf(err, errlen, "%s: no end-of-central-directory record", zip_path);
    return false;
  }
  const uint16_t disk = rd16(base + eocd + 4);
  const uint16_t cd_disk = rd16(base + eocd + 6);
  const uint16_t n_here = rd16(base + eocd + 8);
  const uint16_t n_total = rd16(base + eocd + 10);
  const uint32_t cd_size = rd32(base + eocd + 12);
  const uint32_t cd_off = rd32(base + eocd + 16);
  if (disk != 0 || cd_disk != 0 || n_here != n_total) {
    std::snprintf(err, errlen, "%s: multi-disk archive - not supported", zip_path);
    return false;
  }
  // 0xffff/0xffffffff are the Zip64 escape values (appnote 4.4.1.4).
  // Excluded, not postponed: Explorer's Zip64 support is not there.
  if (n_total == 0xffff || cd_size == 0xffffffff || cd_off == 0xffffffff) {
    std::snprintf(err, errlen, "%s: Zip64 - excluded by design (Explorer compatibility)",
                  zip_path);
    return false;
  }
  if (static_cast<size_t>(cd_off) + cd_size > eocd) {
    std::snprintf(err, errlen, "%s: central directory overruns the end record", zip_path);
    return false;
  }

  entries_.reserve(n_total);
  size_t p = cd_off;
  for (uint32_t i = 0; i < n_total; i++) {
    if (p + 46 > cd_off + cd_size || rd32(base + p) != 0x02014b50) {
      std::snprintf(err, errlen, "%s: central directory truncated at entry %u", zip_path, i);
      return false;
    }
    const uint16_t flags = rd16(base + p + 8);
    const uint16_t method = rd16(base + p + 10);
    const uint16_t dtime = rd16(base + p + 12);
    const uint16_t ddate = rd16(base + p + 14);
    const uint32_t crc = rd32(base + p + 16);
    const uint32_t comp = rd32(base + p + 20);
    const uint32_t uncomp = rd32(base + p + 24);
    const uint16_t nlen = rd16(base + p + 28);
    const uint16_t xlen = rd16(base + p + 30);
    const uint16_t clen = rd16(base + p + 32);
    const uint32_t lho = rd32(base + p + 42);
    const char* nm = reinterpret_cast<const char*>(base + p + 46);
    if (p + 46 + nlen > cd_off + cd_size) {
      std::snprintf(err, errlen, "%s: entry %u name overruns the directory", zip_path, i);
      return false;
    }
    p += 46u + nlen + xlen + clen;

    // Directory rows carry no bytes to serve.
    if (nlen != 0 && nm[nlen - 1] == '/' && uncomp == 0) continue;
    if ((flags & 0x1) != 0) {
      std::snprintf(err, errlen, "%s: %.*s is encrypted - not supported", zip_path, nlen, nm);
      return false;
    }
    if (method != 0 && method != 8) {
      std::snprintf(err, errlen,
                    "%s: %.*s uses method %u - only stored (0) and deflate (8) are served",
                    zip_path, nlen, nm, method);
      return false;
    }
    if (comp == 0xffffffff || uncomp == 0xffffffff) {
      std::snprintf(err, errlen, "%s: %.*s carries Zip64 sizes - excluded by design",
                    zip_path, nlen, nm);
      return false;
    }
    // Skip the local header ONCE, here; its extra field's length may
    // differ from the directory's, so it must be read locally.
    if (static_cast<size_t>(lho) + 30 > map_len_ || rd32(base + lho) != 0x04034b50) {
      std::snprintf(err, errlen, "%s: %.*s has a broken local header", zip_path, nlen, nm);
      return false;
    }
    const uint16_t lnlen = rd16(base + lho + 26);
    const uint16_t lxlen = rd16(base + lho + 28);
    const size_t data_off = static_cast<size_t>(lho) + 30 + lnlen + lxlen;
    if (data_off + comp > map_len_) {
      std::snprintf(err, errlen, "%s: %.*s data overruns the file", zip_path, nlen, nm);
      return false;
    }

    AssetEntry e;
    e.name.assign(nm, nlen);
    e.data = map_ + data_off;
    e.file_off = data_off;
    e.comp_size = comp;
    e.uncomp_size = uncomp;
    e.crc = crc;
    e.deflated = method == 8;
    e.lm_valid = dos_to_imf(ddate, dtime, e.lm);
    e.etag[0] = '"';
    spell_hex8(e.etag + 1, crc);
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
