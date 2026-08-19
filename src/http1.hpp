// HTTP/1.1 framing: ONE framer (phr on the wire bytes, carry only when
// a head splits across receives), ONE writer (per-second prebuilt
// response strings - a response is a single append). Every branch in
// here names its RFC clause.
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

struct H1State {
  // Head bytes a receive ended in the middle of. Capacity survives
  // clear(): a warm connection allocates nothing.
  std::string carry;
  size_t body_skip = 0;  // Content-Length bytes still owed by the wire
  void reset() {
    carry.clear();
    body_skip = 0;
  }
};

enum class H1Verdict : uint8_t { kOpen, kClose };

class Http1 {
 public:
  // Rebuilds the prebuilt responses when the wall-clock second changed
  // (Date is patched by rebuild, never formatted per request).
  void refresh(time_t now);

  // Feed wire bytes; responses land in sink (the connection's out/next,
  // whichever accumulates). kClose: the connection ends once everything
  // queued has drained - error paths and Connection: close alike.
  H1Verdict feed(H1State& st, const char* data, size_t len, std::string& sink);

 private:
  H1Verdict fail(H1State& st, const std::string& resp, std::string& sink);

  time_t sec_ = 0;
  // 200 variants by connection semantics (RFC 9112 §9.3): a persistent
  // 1.1 response carries NO Connection header, a persistent 1.0
  // response echoes keep-alive, anything closing spells close.
  std::string ok_plain_, ok_keep_, ok_close_;
  std::string r400_, r411_, r413_, r431_;
};

}  // namespace webmachine

#endif
