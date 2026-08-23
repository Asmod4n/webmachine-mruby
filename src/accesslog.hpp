// The access log (opt-in): the HOT CORE writes RECORDS, a sibling
// process writes PROSE. Formatting a combined-log line in-process
// measured 71.5ns each - date and number spelling plus an escape scan
// over every request byte; filling a fixed header and memcpying the
// raw strings measures 17ns. So the server ships records over a unix
// socketpair to webmachine-logd (forked by --log, dies with the
// socket), which formats Combined Log Format - the dialect every
// existing reader parses - escapes, and batches to disk on its own
// core, where its 70ns cost nobody.
//
// THE ONE RULE, from the user, verbatim: every line we decide to
// write MUST land on disk. No drop path exists on either side: the
// server's buffer grows until the kernel took the records (the Ring's
// write SQE rides the submit that was happening anyway; a short write
// resumes, a dead daemon is a named refusal), and the daemon's only
// job is to drain, format and write.
//
// This file owns the WIRE CONTRACT between the two: same machine,
// same build, so the struct is the format - no endianness ceremony,
// one version byte so a mismatch refuses instead of misparsing.
#ifndef WEBMACHINE_ACCESSLOG_HPP
#define WEBMACHINE_ACCESSLOG_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace webmachine {

// One response. Followed on the wire by tlen+rlen+ulen raw bytes
// (target, referer, user-agent) and plen peer bytes.
struct LogRec {
  uint8_t version;   // kLogRecVersion, checked by the daemon
  uint8_t flags;     // kLogH2 | kLogNoTrack
  uint16_t status;
  uint32_t bytes;    // %b; 0 spells "-"
  int64_t sec;       // unix time of the answer; the daemon spells it
  uint8_t mlen;      // method bytes follow the header first
  uint8_t plen;      // then the peer's RAW sockaddr (0 = none/unix)
  uint16_t tlen;
  uint16_t rlen;
  uint16_t ulen;
};
inline constexpr uint8_t kLogRecVersion = 3;
inline constexpr uint8_t kLogH2 = 1;  // spell "HTTP/2", not "HTTP/1.1"
// The peer sent DNT: 1 or Sec-GPC: 1 - "do not track me". Respected:
// the daemon caps this record's %h at anon even when the operator
// chose privacy `none`. (A future debug build with tracing active
// will log everything by design - the user's stated exception.)
inline constexpr uint8_t kLogNoTrack = 2;

struct AccessLog {
  bool enabled = false;
  std::string buf;
  std::string flight;
  bool in_flight = false;
  int64_t sec = 0;  // refreshed once per second by on_tick

  void line(const void* peer, size_t plen, const char* method, size_t mlen, const char* target,
            size_t tlen, uint8_t flags, uint16_t status, size_t body_bytes, const char* ref,
            size_t rlen, const char* ua, size_t ulen) {
    // Truncation caps are the wire fields' widths; a 64K header is
    // kMaxHead-bounded before it ever gets here.
    if (mlen > 255) mlen = 255;
    if (plen > 255) plen = 255;
    if (tlen > 65535) tlen = 65535;
    if (rlen > 65535) rlen = 65535;
    if (ulen > 65535) ulen = 65535;
    LogRec r;
    r.version = kLogRecVersion;
    r.flags = flags;
    r.status = status;
    r.bytes = body_bytes > 0xffffffffull ? 0xffffffffu : static_cast<uint32_t>(body_bytes);
    r.sec = sec;
    r.mlen = static_cast<uint8_t>(mlen);
    r.plen = static_cast<uint8_t>(plen);
    r.tlen = static_cast<uint16_t>(tlen);
    r.rlen = static_cast<uint16_t>(rlen);
    r.ulen = static_cast<uint16_t>(ulen);
    buf.append(reinterpret_cast<const char*>(&r), sizeof r);
    if (mlen != 0) buf.append(method, mlen);
    if (plen != 0) buf.append(static_cast<const char*>(peer), plen);
    if (tlen != 0) buf.append(target, tlen);
    if (rlen != 0) buf.append(ref, rlen);
    if (ulen != 0) buf.append(ua, ulen);
  }
};

}  // namespace webmachine

#endif
