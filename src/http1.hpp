// HTTP/1.1 framing as a Ring App: ONE framer (phr on the wire bytes,
// carry only when a head splits across receives), ONE writer (prebuilt
// response strings, the running second PATCHES 29 date bytes in place -
// a response is a single append). Every branch names its RFC clause.
// The Ring knows none of this; it hands bytes in and drains the sink.
#ifndef WEBMACHINE_HTTP1_HPP
#define WEBMACHINE_HTTP1_HPP

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>

namespace webmachine {

// RFC 9110 §5.4 allows refusing oversized fields; 8k is the fleet
// convention (nginx, h2o) and bounds one head's work - 431 past it.
inline constexpr size_t kMaxHead = 8192;
// Bodies are skipped at this layer, but skipping is still work; 1 MiB
// bounds it - 413 past it (RFC 9110 §15.5.14).
inline constexpr size_t kMaxBody = 1u << 20;
inline constexpr size_t kMaxHeaders = 64;

class Http1 {
 public:
  struct Conn {
    // Head bytes a receive ended in the middle of. Capacity survives
    // clear(): a warm connection allocates nothing.
    std::string carry;
    size_t body_skip = 0;  // Content-Length bytes still owed by the wire
    void reset() {
      carry.clear();
      body_skip = 0;
    }
  };

  // Builds the prebuilt responses once and stamps the current date.
  Http1();

  // The Ring's per-wake hook: patch the date bytes when the wall-clock
  // second changed. Never runs per request.
  void on_tick();

  // Feed wire bytes; responses land in sink (the connection's out/next,
  // whichever accumulates). False: the connection ends once everything
  // queued has drained - error paths and Connection: close alike.
  bool feed(Conn& st, const char* data, size_t len, std::string& sink);

 private:
  // A prebuilt response whose date field sits at a fixed offset.
  struct Resp {
    std::string bytes;
    size_t date_off = 0;
  };

  bool fail(Conn& st, const Resp& resp, std::string& sink);

  time_t sec_ = 0;
  // 200 variants by connection semantics (RFC 9112 §9.3): a persistent
  // 1.1 response carries NO Connection header, a persistent 1.0
  // response echoes keep-alive, anything closing spells close.
  Resp ok_plain_, ok_keep_, ok_close_;
  Resp r400_, r411_, r413_, r431_;
};

}  // namespace webmachine

#endif
