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

// The bound resource (resource.hpp owns the definition; Http1 stays
// mruby-free). resource_run answers decision + render inside ONE VM
// frame; resource_exception_begin lends a pending exception's message
// (copy before the next mruby call).
struct Resource;
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, std::string* body,
                      bool* have_body);
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);

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
    uint8_t listener = 0;  // which listener accepted - whose app this is
    void reset(uint8_t li) {
      carry.clear();
      body_skip = 0;
      listener = li;
    }
  };

  // Builds every response the flow can speak, once, and stamps the
  // date. `res` (with its two flags, readable only where resource.hpp
  // is included) carries the runtime tier: dynamic flow nodes and/or a
  // per-request body. Null = fully konst.
  explicit Http1(const flow::KonstSet& ks = {}, const Resource* res = nullptr,
                 bool dynamic_nodes = false, bool dynamic_body = false);

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
  // prefix + hand-spelled Content-Length + (unless HEAD) the lent body.
  static void assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                       bool head_only);
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];  // every status here came from the tables
  }
  bool fail(Conn& st, uint16_t status, std::string& sink);

  time_t sec_ = 0;
  std::vector<Variants> store_;
  std::array<uint8_t, 600> index_ {};  // status -> store_ slot
  Variants ok_head_;  // 200 for HEAD: the same head, no body bytes
  // Heads up to (not including) Content-Length: the assembly points
  // for per-request bodies (200) and for exceptions answering as the
  // negotiated type (500).
  Variants ok_prefix_;
  Variants err_prefix_;
  // One konst vector per method, the method folded in at bind time
  // (B12/B10 never re-compare method strings per request).
  flow::KonstSet konst_;
  const Resource* res_ = nullptr;
  bool dynamic_nodes_ = false;
  bool dynamic_body_ = false;
  bool bound_ = false;  // any runtime tier at all
  std::string body_;    // the run frame's rendered bytes; capacity survives
};

}  // namespace webmachine

#endif
