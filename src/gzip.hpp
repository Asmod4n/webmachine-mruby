// Dynamic-body gzip (#147): the SAME wire shape assets.cpp hand-builds
// for a ZIP method-8 entry - RFC 1952 header + trailer around a raw
// DEFLATE stream - built here at REQUEST time instead of read from a
// mapping, because a dynamic body does not exist until a resource
// callback renders it. One-shot: the whole body is already in memory
// (Resource::to_html returns a String, never a stream), so there is no
// reason to hold a persistent zng_stream across calls the way #172's
// permessage-deflate streaming eventually will.
#ifndef WEBMACHINE_GZIP_HPP
#define WEBMACHINE_GZIP_HPP

#include <zlib-ng.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <string>

namespace webmachine::gzip {

// RFC 1952 2.3.1: magic, CM=8 (deflate), FLG=0, MTIME=0 (unknown - no
// clock this framing can vouch for, same "unknown" as assets.cpp's
// kGzHdr), XFL=0, OS=0xff (unknown). Byte-identical to AssetEntry's
// gz_hdr; kept as this tier's own constant rather than shared, because
// sharing it would tie a per-request path to an asset-tier type for
// ten static bytes that never change.
inline constexpr unsigned char kHeader[10] = {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff};

// Level 1 (Z_BEST_SPEED, #147: dynamic bodies live at the fast end of
// the scale only - zstd -19 / brotli q11 are an asset BUILD's job,
// never a response's). Raw deflate (windowBits -15): no zlib/gzip
// wrapper from zlib-ng itself - the header above and the trailer below
// ARE the wrapper, hand-built the same way assets.cpp's is, so both
// tiers emit the exact same envelope shape around a deflate stream.
//
// False = zlib-ng refused compressing (allocation failure, or `in` at
// or above 4 GiB - avail_in is uint32_t and no resource body comes
// anywhere close). The caller's answer is to serve identity instead:
// compression is an optimization on top of an always-correct fallback,
// never a reason to fail the response (#147: identity is ALWAYS
// available for a dynamic body, so nothing here may 406 or 500).
inline bool compress(const std::string& in, std::string& out) {
  if (in.size() >= std::numeric_limits<uint32_t>::max()) return false;
  zng_stream strm{};
  if (zng_deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    return false;
  }
  const unsigned long bound = zng_deflateBound(&strm, static_cast<unsigned long>(in.size()));
  out.assign(reinterpret_cast<const char*>(kHeader), sizeof(kHeader));
  const size_t body_off = out.size();
  out.resize(body_off + bound);
  strm.next_in = reinterpret_cast<const uint8_t*>(in.data());
  strm.avail_in = static_cast<uint32_t>(in.size());
  strm.next_out = reinterpret_cast<uint8_t*>(out.data()) + body_off;
  strm.avail_out = static_cast<uint32_t>(bound);
  const int rc = zng_deflate(&strm, Z_FINISH);
  const size_t produced = strm.total_out;
  zng_deflateEnd(&strm);
  // deflateBound sized the buffer for one call to finish the WHOLE
  // input in a single shot; anything but Z_STREAM_END here means
  // zlib-ng itself refused (not "needs another call" - there isn't
  // going to be one).
  if (rc != Z_STREAM_END) return false;
  out.resize(body_off + produced);

  const uint32_t crc = zng_crc32_z(0, reinterpret_cast<const uint8_t*>(in.data()), in.size());
  const uint32_t isize = static_cast<uint32_t>(in.size());  // RFC 1952: length mod 2^32
  unsigned char trailer[8];
  trailer[0] = static_cast<unsigned char>(crc);
  trailer[1] = static_cast<unsigned char>(crc >> 8);
  trailer[2] = static_cast<unsigned char>(crc >> 16);
  trailer[3] = static_cast<unsigned char>(crc >> 24);
  trailer[4] = static_cast<unsigned char>(isize);
  trailer[5] = static_cast<unsigned char>(isize >> 8);
  trailer[6] = static_cast<unsigned char>(isize >> 16);
  trailer[7] = static_cast<unsigned char>(isize >> 24);
  out.append(reinterpret_cast<const char*>(trailer), sizeof(trailer));
  return true;
}

}  // namespace webmachine::gzip

#endif
