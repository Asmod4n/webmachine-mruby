// Assets out of ONE ZIP file (#170): one fd, one mmap, a table built
// at add_route and never touched again. Only the Central Directory is
// read (its sizes are always right; Local Header sizes may be zeroed
// by data descriptors, flag bit 3) - each entry's local header is
// skipped once at setup, never per request.
//
// THE ZIP METHOD ENCODES THE DELIVERY DECISION: method 8 (deflate) is
// served as Content-Encoding: gzip - a method-8 entry IS a raw deflate
// stream, i.e. exactly the body of a gzip response; the two fields the
// gzip trailer needs (CRC-32, uncompressed size) sit in the Central
// Directory. Method 0 (stored) is served as identity. One field
// compare at runtime - no table, no heuristic, no percentage.
// (History: an old rule said "never infer the coding from the method".
// It held when method 0 was ambiguous - identity OR brotli in a .br
// sibling entry. With ONE entry per file and no siblings, method 0 is
// unambiguously identity, and the inference is exactly right.)
//
// WHY ONLY DEFLATE (user decision, final): the file must survive the
// Windows Explorer - open, read, AND change. Explorer writes deflate
// and cannot be taught stored or zstd, and it cannot keep sibling
// entries in sync. With one deflate-or-stored entry per file, an
// Explorer edit degrades cleanly (a replaced JPEG becomes method 8 and
// ships as gzip: wasteful, correct, fixed by the next build) instead
// of breaking. Zip64 is EXCLUDED, not postponed - Explorer's Zip64
// support is historically bad: < 65535 entries and < 4 GB is a
// requirement, refused by name at setup.
//
// Path traversal is structurally impossible, not filtered: a request
// can only name what the table holds. No ..-parsing, no realpath, no
// CVE class.
#ifndef WEBMACHINE_ASSETS_HPP
#define WEBMACHINE_ASSETS_HPP

#include <sys/uio.h>  // struct iovec: a source hands out pointers, not bytes

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "flow_walk.hpp"
#include "http.hpp"

namespace webmachine {

// Everything about one served entry, computed at setup. `data` points
// into the mapping, past the local header - the deflate (or stored)
// bytes the wire carries untouched.
struct AssetEntry {
  std::string name;  // the lookup key: the archive name, no leading slash
  const char* data = nullptr;
  // Where `data` sits in the ZIP FILE - the splice path (#168) reads
  // the same page-cache pages through the fd that the mapping shows.
  size_t file_off = 0;
  size_t comp_size = 0;
  size_t uncomp_size = 0;
  uint32_t crc = 0;
  bool deflated = false;  // ZIP method 8; false = stored (method 0)
  bool lm_valid = false;  // a DOS date of 0 has no meaning to serve
  // ETag = the Central Directory's CRC-32, quoted. It names the
  // UNCOMPRESSED data, and because exactly ONE representation is ever
  // served per entry, no collision across coding boundaries is
  // possible - no suffix needed (RFC 9110 §8.8.3.3).
  char etag[10] = {};  // "xxxxxxxx"
  char lm[http::kDateLen] = {};  // Last-Modified, IMF-fixdate
  std::string ctype;  // from the extension, decided once at setup

  // Prebuilt h1 header sections (status line through the blank line),
  // date patched LAZILY at answer time - a per-second sweep over
  // thousands of entries would be work nobody asked for; an entry
  // nobody requests is never patched. Indexed by Variant.
  struct Resp {
    std::string bytes;
    size_t date_off = 0;
    time_t sec = 0;  // the second the date bytes belong to
  };
  Resp h200[3];
  Resp h304[3];

  // gzip framing around the deflate bytes (method 8 only). The header
  // is constant ONLY because MTIME=0 and OS=0xff - both legal
  // "unknown" per RFC 1952; a real mtime would make it per-entry.
  unsigned char gz_hdr[10] = {};
  unsigned char gz_trailer[8] = {};

  // h2 header blocks (never-indexed HPACK), built by Http1 at setup -
  // the HPACK spelling lives in http2.cpp, not here. Date-free: the
  // date rides the encoder lane per response.
  std::string h2_200;
  std::string h2_304;
};

class Assets {
 public:
  // RFC 9112 §9.3 connection spellings, same shape as Http1's
  // Variants: a persistent 1.1 response carries no Connection header,
  // a persistent 1.0 echoes keep-alive, anything closing spells close.
  enum Variant : uint8_t { kPlain = 0, kKeep = 1, kClose = 2 };

  Assets() = default;
  ~Assets();
  Assets(const Assets&) = delete;
  Assets& operator=(const Assets&) = delete;

  // Parse + map + prebuild. False leaves the named refusal in err -
  // Zip64, encryption, a method that is neither 0 nor 8, a truncated
  // directory: all name themselves, nothing degrades silently.
  bool open(const char* zip_path, char* err, size_t errlen);

  // path is the request-target (origin-form): the query is stripped,
  // the leading slash dropped, and the rest must equal a table name
  // byte for byte (no percent-decoding: entries are named by their
  // table row, not by an escape grammar). Null = not an asset; the
  // caller falls through to its app resource.
  AssetEntry* find(const char* path, size_t len);

  // The asset tier's whole decision, in the graph's own order (conneg
  // before preconditions, C..F before G..):
  //   405 anything but GET/HEAD (501 for methods the tree cannot name)
  //   406 method-8 entry, Accept-Encoding present, gzip not acceptable
  //   412 If-Match present and the strong comparison fails
  //   304 If-None-Match matches (weak comparison)
  //   200 otherwise
  // The 406 deviates from a SHOULD by name: §12.5.3 says a server
  // should fall back to no coding - assuming it CAN produce an
  // uncompressed representation. This tree deliberately cannot (no
  // inflate anywhere); §15.5.7 sanctions the refusal.
  uint16_t verdict(const AssetEntry& e, flow::Method m, const flow::ReqFacts& f,
                   const http::ReqValues& vals) const;

  // Append the h1 HEADER SECTION for a verdict this tier owns (200,
  // 304, 405, 406) - never body bytes: delivery is the caller's (#168,
  // it owns the budget and the transfer state). 412/501 stay with the
  // caller's shared status store - they carry nothing asset-specific.
  void answer_head(AssetEntry& e, uint16_t status, Variant v, const char* date, time_t sec,
                   std::string& sink);

  // Ranged heads (#148) are built per request - the rare path, and
  // they carry three request-dependent numbers no prebuild can hold.
  // The window [first, last] counts octets of the WIRE body
  // (wire_len), i.e. the selected representation's encoded bytes.
  void answer_206_head(const AssetEntry& e, Variant v, size_t first, size_t last,
                       const char* date, std::string& sink);
  void answer_416_head(const AssetEntry& e, Variant v, const char* date, std::string& sink);

  // The wire body and the ONE place that knows its shape: gzip header
  // + deflate bytes + trailer for method 8, the stored bytes alone for
  // method 0. Both protocols go through here - h1 chunks, h2 frames,
  // parked continuations - so the segment arithmetic exists once.
  static size_t wire_len(const AssetEntry& e) {
    return e.deflated ? e.comp_size + 18 : e.comp_size;
  }
  // POINTERS, not bytes: [off, off+n) of the wire body as up to three
  // iovecs - the constant gzip header, the deflate stream WHERE IT
  // LIES IN THE MAPPING, the trailer. Nothing is copied; the kernel
  // reads the mapping directly on send. Returns how many iovecs were
  // filled. This is what #168 means by "a source delivers a plan": the
  // one copy that remains is the kernel's, into the socket buffer.
  static unsigned wire_iov(const AssetEntry& e, size_t off, size_t n, struct iovec* iov);
  // The copying form, kept for the paths that must own their bytes:
  // h2 DATA frames interleave with other streams' frames in one sink,
  // so their payload cannot be a pointer that outlives the round.
  static void copy_wire(const AssetEntry& e, size_t off, size_t n, std::string& sink);

  std::vector<AssetEntry>& entries() { return entries_; }
  // The one fd, kept open past the mmap: the splice path (#168) will
  // read from it; it is part of ring.hpp's kFdReserve arithmetic.
  int fd() const { return fd_; }

 private:
  static void patch_date(AssetEntry::Resp& r, const char* date, time_t sec);

  int fd_ = -1;
  const char* map_ = nullptr;
  size_t map_len_ = 0;
  std::vector<AssetEntry> entries_;  // sorted by name; find binary-searches
  // Shared refusal heads (405 with Allow: GET, HEAD / 406 with Vary),
  // one triple each, date patched lazily like the entry heads.
  AssetEntry::Resp s405_[3];
  AssetEntry::Resp s406_[3];
};

}  // namespace webmachine

#endif
