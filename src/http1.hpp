// HTTP/1.1 framing as a Ring App: ONE framer (phr on the wire bytes,
// carry only when a head splits across receives), ONE writer (prebuilt
// response strings for every status the flow can speak, the running
// second PATCHES 29 date bytes in place - a response is a single
// append), ONE flow (the webmachine graph decides every status; the
// framer only ever decides wire validity). Every branch names its RFC
// clause. The Ring knows none of this; it hands bytes in and drains
// the sink.
#ifndef WEBMACHINE_HTTP1_HPP
#define WEBMACHINE_HTTP1_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "flow_walk.hpp"

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

  // Builds every response the flow can speak, once, and stamps the
  // date. The KonstSet is the bound resource - webmachine-ruby's
  // defaults when none was bound, the mruby bridge's product otherwise.
  explicit Http1(const flow::KonstSet& ks = {});

  // The Ring's per-wake hook: patch the date bytes when the wall-clock
  // second changed. Never runs per request.
  void on_tick();

  // Feed wire bytes; responses land in sink (the connection's out/next,
  // whichever accumulates). False: the connection ends once everything
  // queued has drained - wire-invalidity paths and Connection: close.
  bool feed(Conn& st, const char* data, size_t len, std::string& sink);

 private:
  // A prebuilt response whose date field sits at a fixed offset.
  struct Resp {
    std::string bytes;
    size_t date_off = 0;
  };
  // Connection semantics per RFC 9112 §9.3: a persistent 1.1 response
  // carries NO Connection header, a persistent 1.0 response echoes
  // keep-alive, anything closing spells close.
  struct Variants {
    Resp plain, keep, close;
  };

  void build_status(uint16_t status, const char* extra, const char* body);
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];  // every status here came from the tables
  }
  bool fail(Conn& st, uint16_t status, std::string& sink);

  time_t sec_ = 0;
  std::vector<Variants> store_;
  std::array<uint8_t, 600> index_ {};  // status -> store_ slot
  Variants ok_head_;  // 200 for HEAD: the same head, no body bytes
  // One konst vector per method, the method folded in at bind time
  // (B12/B10 never re-compare method strings per request).
  flow::KonstSet konst_;
};

}  // namespace webmachine

#endif
