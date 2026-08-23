// permessage-deflate (#175 round two, RFC 7692): the NEGOTIATION and
// the CODEC, and nothing else. No mruby, no connection, no IO - the
// same cut websocket.hpp makes for the framing, so both halves can be
// driven from a test binary before a socket exists.
//
// WHY THE SYSTEM zlib AND NOT libdeflate (which this tree already
// carries for #170's zip reader): 7692 is a STREAM. A message is
// compressed with Z_SYNC_FLUSH and the LZ77 window is carried into the
// next one (7.1.1, "context takeover"), so the compressor's state
// outlives every single call. libdeflate's whole-buffer API cannot
// express that at all - it is not slower here, it is unable. zlib's
// z_stream is, and libz.so.1 is on every server distribution (see
// mrbgem.rake for the standing rule).
//
// WHAT IT COSTS, per connection, said in bytes because that is the
// number that decides the default: zlib's own arithmetic (deflate.c)
// is (1 << (windowBits+2)) + (1 << (memLevel+9)) for the compressor -
// 128 KiB + 128 KiB at the defaults - plus (1 << windowBits) + state
// for the decompressor, about 40 KiB. Call it 296 KiB PER PEER, on a
// tree whose connection capacity is derived in the tens of thousands
// (#169). That is why the extension is OPT-IN per route
// (WebsocketResource.permessage_deflate?, default false) and why the
// streams are built LAZILY, on the first message that actually needs
// one: h2.hpp already carries the measurement that eager
// per-connection objects cost -12% throughput and +58% p99 at 7000
// idle connections, and this object is two orders of magnitude bigger
// than the one that did that.
#ifndef WEBMACHINE_WSDEFLATE_HPP
#define WEBMACHINE_WSDEFLATE_HPP

#include <zlib.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>

namespace webmachine {
namespace wsdeflate {

// THE SMALLEST WINDOW A RAW DEFLATE STREAM CAN HAVE, and it is not
// 8: deflateInit2 checks `windowBits == 8 && wrap != 1` and answers
// Z_STREAM_ERROR, because the 256-byte window has a bug zlib never
// fixed. 7692 lets a client name 8 anyway (7.1.2.1: 8 to 15
// inclusive), and this one number answers both directions of that.
//
// server_max_window_bits=8 is DECLINED by name rather than answered
// with 9 - a response naming a larger window than the offer is what
// 7.1.2.1 forbids, and a response naming 8 while compressing with 9
// would hand the peer a stream its inflater cannot follow.
//
// client_max_window_bits=8 is accepted and echoed, and the
// DECOMPRESSOR built one bit larger: the client's zlib cannot produce
// an 8-bit window either, so 9 is what will actually arrive.
inline constexpr uint8_t kMinRawWindowBits = 9;

// RFC 7692 7.2.1 step 4 / 7.2.2 step 1: a Z_SYNC_FLUSH ends the
// deflate stream with an empty stored block, and the four bytes that
// spells are removed by the sender and put back by the receiver. They
// are not payload; they are the frame boundary the extension does not
// need to repeat.
inline constexpr unsigned char kSyncTail[4] = {0x00, 0x00, 0xff, 0xff};

// What one negotiation settled on. `on` false means every other field
// is meaningless: this connection speaks plain RFC 6455.
struct Params {
  bool on = false;
  bool server_no_context_takeover = false;
  bool client_no_context_takeover = false;
  uint8_t server_max_window_bits = 15;  // what THIS side compresses with
  uint8_t client_max_window_bits = 15;  // what the peer compresses with
};

namespace detail {

constexpr bool is_ows(char c) { return c == ' ' || c == '\t'; }

// RFC 9110 5.6.2's token, which is what 7692 4.2's extension-param
// names and unquoted values are.
constexpr bool is_tchar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
         c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' ||
         c == '~';
}

inline bool ci_eq(const char* s, size_t n, const char* lit, size_t litn) {
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// 8..15 with no leading zeroes (7.1.2.1 says so in as many words), so
// "08" and "015" are refusals and not 8 and 15.
inline bool window_bits(const char* v, size_t n, uint8_t& out) {
  if (n == 0 || n > 2) return false;
  if (v[0] == '0') return false;
  unsigned x = 0;
  for (size_t i = 0; i < n; i++) {
    if (v[i] < '0' || v[i] > '9') return false;
    x = x * 10 + static_cast<unsigned>(v[i] - '0');
  }
  if (x < 8 || x > 15) return false;
  out = static_cast<uint8_t>(x);
  return true;
}

}  // namespace detail

// ONE Sec-WebSocket-Extensions field value - a comma-separated offer
// list (RFC 7692 4.2, RFC 9110 5.6.1) - answered with the FIRST
// permessage-deflate offer this endpoint can accept. `answer` gets the
// response field value; `out` gets what the codec must then do.
//
// Declining is never an error: 7692 5.1 lets a server ignore an offer
// it does not want, and the connection is then a perfectly good plain
// websocket. So this returns false for "nothing here", never for "this
// handshake is bad" - the ONE thing that could fail a handshake is a
// malformed header, and a malformed extension header is indistinguish-
// able from an extension we do not offer.
inline bool negotiate(const char* v, size_t len, Params& out, std::string& answer) {
  size_t i = 0;
  while (i < len) {
    // ---- one offer, up to the next top-level comma
    while (i < len && (detail::is_ows(v[i]) || v[i] == ',')) i++;
    const size_t name_at = i;
    while (i < len && detail::is_tchar(v[i])) i++;
    const size_t name_len = i - name_at;
    bool ok = detail::ci_eq(v + name_at, name_len, "permessage-deflate", 18);

    Params p;
    p.on = true;
    bool seen_snct = false, seen_cnct = false, seen_smwb = false, seen_cmwb = false;
    bool echo_cmwb = false;

    while (true) {
      while (i < len && detail::is_ows(v[i])) i++;
      if (i >= len || v[i] != ';') break;
      i++;  // the ';'
      while (i < len && detail::is_ows(v[i])) i++;
      const size_t pn_at = i;
      while (i < len && detail::is_tchar(v[i])) i++;
      const size_t pn_len = i - pn_at;
      while (i < len && detail::is_ows(v[i])) i++;
      const char* pv = nullptr;
      size_t pv_len = 0;
      bool have_value = false;
      if (i < len && v[i] == '=') {
        i++;
        while (i < len && detail::is_ows(v[i])) i++;
        have_value = true;
        if (i < len && v[i] == '"') {
          // 9110 5.6.4: a quoted-string. 7692's own values are all
          // tokens, but a client is allowed to quote them and some do.
          i++;
          pv = v + i;
          while (i < len && v[i] != '"') {
            if (v[i] == '\\' && i + 1 < len) i++;  // quoted-pair
            i++;
          }
          pv_len = static_cast<size_t>(v + i - pv);
          if (i < len) i++;  // the closing quote
        } else {
          pv = v + i;
          while (i < len && detail::is_tchar(v[i])) i++;
          pv_len = static_cast<size_t>(v + i - pv);
        }
      }
      if (!ok) continue;  // an offer already refused is only being skipped past

      // 7692 7.1: an extension parameter this endpoint does not know,
      // a value where none belongs, or the same parameter twice makes
      // the OFFER unacceptable - not the handshake. The next offer in
      // the list gets its turn.
      if (detail::ci_eq(v + pn_at, pn_len, "server_no_context_takeover", 26)) {
        if (seen_snct || have_value) { ok = false; continue; }
        seen_snct = true;
        p.server_no_context_takeover = true;
      } else if (detail::ci_eq(v + pn_at, pn_len, "client_no_context_takeover", 26)) {
        if (seen_cnct || have_value) { ok = false; continue; }
        seen_cnct = true;
        p.client_no_context_takeover = true;
      } else if (detail::ci_eq(v + pn_at, pn_len, "server_max_window_bits", 22)) {
        // 7.1.2.1: in an OFFER this parameter always carries a value.
        uint8_t b = 0;
        if (seen_smwb || !have_value || !detail::window_bits(pv, pv_len, b) ||
            b < kMinRawWindowBits) {
          ok = false;
          continue;
        }
        seen_smwb = true;
        p.server_max_window_bits = b;
      } else if (detail::ci_eq(v + pn_at, pn_len, "client_max_window_bits", 22)) {
        // 7.1.2.2: with or without a value. Without one it says only
        // that the client would UNDERSTAND the parameter in the
        // response - the client still uses 15 unless the response
        // names something smaller, and this endpoint names nothing.
        // With one, the value is what the client would rather use, so
        // it is echoed and the decompressor is built that small.
        if (seen_cmwb) { ok = false; continue; }
        seen_cmwb = true;
        if (have_value) {
          uint8_t b = 0;
          if (!detail::window_bits(pv, pv_len, b)) { ok = false; continue; }
          p.client_max_window_bits = b;
          echo_cmwb = true;
        }
      } else {
        ok = false;  // 7.1: an unknown parameter
      }
    }

    if (ok) {
      out = p;
      answer.assign("permessage-deflate");
      // Only what was OFFERED goes back (7.1.2.1: a response value must
      // not exceed the offer; 7.1.2.2: client_max_window_bits may not
      // appear at all unless the client asked for it). The two
      // no_context_takeover parameters are echoed as confirmation -
      // the client promised, and this endpoint says it heard.
      if (p.server_no_context_takeover) answer.append("; server_no_context_takeover");
      if (p.client_no_context_takeover) answer.append("; client_no_context_takeover");
      if (seen_smwb) {
        answer.append("; server_max_window_bits=")
            .append(std::to_string(static_cast<unsigned>(p.server_max_window_bits)));
      }
      if (echo_cmwb) {
        answer.append("; client_max_window_bits=")
            .append(std::to_string(static_cast<unsigned>(p.client_max_window_bits)));
      }
      return true;
    }
    // Past this offer's own comma, whatever was left of it.
    while (i < len && v[i] != ',') i++;
  }
  return false;
}

// The two zlib streams of ONE connection, built on first use and not
// before (see the header: 296 KiB is not a thing to hand out at
// accept). Neither is a value type - a z_stream holds pointers into
// its own allocation - so this neither copies nor moves.
class Codec {
 public:
  Codec() = default;
  Codec(const Codec&) = delete;
  Codec& operator=(const Codec&) = delete;
  ~Codec() {
    if (inf_on_) inflateEnd(&inf_);
    if (def_on_) deflateEnd(&def_);
  }

  void configure(const Params& p) { p_ = p; }
  const Params& params() const { return p_; }

  // ---- receiving: 7692 7.2.2

  // Payload bytes of a compressed message, as they arrive. `sink` is
  // called with each run of decompressed bytes and answers false when
  // the message may not grow any further (max_message) - which is the
  // ONLY guard against a decompression bomb, and the reason the
  // compressed side is deliberately not bounded: a peer may spend all
  // the bandwidth it likes, it may not choose how much of THIS
  // process's heap the result takes.
  //   0 = fed, -1 = not a DEFLATE stream, -2 = the sink said stop
  template <class Sink>
  int inflate_some(const char* in, size_t n, Sink&& sink) {
    if (!inflate_ready()) return -1;
    inf_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
    inf_.avail_in = static_cast<uInt>(n);
    return pump(sink);
  }

  // The message ended: 7.2.2 step 1 puts the four bytes back that the
  // sender removed, and what falls out of them is the tail of the
  // message.
  template <class Sink>
  int inflate_finish(Sink&& sink) {
    if (!inflate_ready()) return -1;
    inf_.next_in = const_cast<Bytef*>(kSyncTail);
    inf_.avail_in = sizeof(kSyncTail);
    const int rc = pump(sink);
    if (rc != 0) return rc;
    // 7.1.1.1: without context takeover the peer starts every message
    // from an empty window, so this side must too. A stream that ended
    // (the peer sent a BFINAL block) is reset either way - nothing can
    // follow a finished deflate stream.
    if (p_.client_no_context_takeover || inf_ended_) {
      inflateReset(&inf_);
      inf_ended_ = false;
    }
    return 0;
  }

  // ---- sending: 7692 7.2.1

  // One whole message compressed into `out`, ready to be the payload
  // of a frame with RSV1 set. False = zlib refused (an allocation, or
  // a stream that broke); the caller's answer is to send the message
  // uncompressed, which 6455 always allows and 7692 6 explicitly does
  // - and this codec then never compresses again on this connection,
  // because a half-fed context is a stream the peer can no longer
  // follow.
  bool compress(const char* in, size_t n, std::string& out) {
    // avail_in is a uInt and has been since 1995. No route's
    // max_message comes near 4 GiB, and the one that did would get a
    // silently truncated message rather than a refusal - so it is a
    // refusal, and the caller sends the thing uncompressed.
    if (n > std::numeric_limits<uInt>::max()) return false;
    if (def_broken_ || !deflate_ready()) return false;
    out.clear();
    def_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
    def_.avail_in = static_cast<uInt>(n);
    unsigned char buf[8192];
    for (;;) {
      def_.next_out = buf;
      def_.avail_out = sizeof(buf);
      const int rc = deflate(&def_, Z_SYNC_FLUSH);
      if (rc != Z_OK && rc != Z_BUF_ERROR) {
        def_broken_ = true;
        return false;
      }
      out.append(reinterpret_cast<const char*>(buf), sizeof(buf) - def_.avail_out);
      // Z_SYNC_FLUSH is done when it stopped needing room: zlib's own
      // "avail_out != 0 means the flush completed" (deflate.c).
      if (def_.avail_out != 0) break;
    }
    // 7.2.1 step 4: drop the 00 00 FF FF the flush just wrote. An
    // EMPTY message flushes to exactly those four plus one byte of
    // empty-block header, so what is left is one byte - which is the
    // shortest legal compressed payload and not a bug.
    if (out.size() < sizeof(kSyncTail) ||
        std::memcmp(out.data() + out.size() - sizeof(kSyncTail), kSyncTail,
                    sizeof(kSyncTail)) != 0) {
      def_broken_ = true;
      return false;
    }
    out.resize(out.size() - sizeof(kSyncTail));
    // 7.1.1.1: the client asked this side to start every message from
    // an empty window, so the window goes away between messages. It is
    // the same z_stream - the 256 KiB stays; what resets is the
    // history the peer's inflater is allowed to assume.
    if (p_.server_no_context_takeover) deflateReset(&def_);
    return true;
  }

 private:
  bool inflate_ready() {
    if (inf_on_) return true;
    // Raw deflate (a negative windowBits): 7692 carries no zlib or
    // gzip wrapper, the frame IS the envelope. The window is what the
    // negotiation said the peer would use: at 9 bits that is 512 bytes
    // instead of the 32 KiB a full one costs, per connection, and a
    // decompressor may always be LARGER than the compressor was, never
    // smaller.
    //
    // Never below 9, though, and the reason is the same zlib rule that
    // makes this side decline server_max_window_bits=8: no zlib
    // compressor can produce a raw 8-bit window, so a client that
    // asked for 8 will be compressing with 9 whatever it meant to say.
    // One bit larger than promised can only ever be right; one bit
    // smaller would fail a stream that is perfectly legal.
    const int bits = p_.client_max_window_bits < kMinRawWindowBits
                         ? kMinRawWindowBits
                         : p_.client_max_window_bits;
    if (inflateInit2(&inf_, -bits) != Z_OK) return false;
    inf_on_ = true;
    return true;
  }

  bool deflate_ready() {
    if (def_on_) return true;
    // Z_BEST_SPEED, the same end of the scale gzip.hpp's dynamic
    // bodies live at (#147: a response compresses at request time, so
    // it compresses fast). It costs less here than it does there,
    // because context takeover means the dictionary - not the search
    // effort - is what makes a chatty connection's messages small.
    // memLevel 8 is zlib's own default and stays it: deviating is a
    // ratio-against-memory trade, and this tree does not publish those
    // without a measurement on real hardware.
    if (deflateInit2(&def_, Z_BEST_SPEED, Z_DEFLATED,
                     -static_cast<int>(p_.server_max_window_bits), 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
      def_broken_ = true;
      return false;
    }
    def_on_ = true;
    return true;
  }

  template <class Sink>
  int pump(Sink& sink) {
    unsigned char buf[8192];
    for (;;) {
      inf_.next_out = buf;
      inf_.avail_out = sizeof(buf);
      const int rc = inflate(&inf_, Z_NO_FLUSH);
      if (rc == Z_STREAM_END) inf_ended_ = true;
      else if (rc != Z_OK && rc != Z_BUF_ERROR) return -1;
      const size_t got = sizeof(buf) - inf_.avail_out;
      if (got != 0 && !sink(reinterpret_cast<const char*>(buf), got)) return -2;
      if (inf_.avail_out != 0) return 0;  // zlib had room left: it is done
    }
  }

  Params p_;
  z_stream inf_{};
  z_stream def_{};
  bool inf_on_ = false;
  bool def_on_ = false;
  bool def_broken_ = false;
  bool inf_ended_ = false;
};

}  // namespace wsdeflate
}  // namespace webmachine

#endif
