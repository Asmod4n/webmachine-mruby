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

#include <sys/uio.h>  // struct iovec: a round's plan is pointers, not bytes

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "flow_walk.hpp"
#include "http.hpp"

namespace webmachine {

// The bound resource (resource.hpp owns the definition; Http1 stays
// mruby-free). resource_run answers decision + render inside ONE VM
// frame; resource_exception_begin lends a pending exception's message
// (copy before the next mruby call).
struct Resource;
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, std::string* body,
                      bool* have_body);
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);

// h2.hpp owns the definition (it pulls lshpack.h; this header stays
// lean). A connection that never speaks the preface carries only the
// null pointer. h2_free lives in http2.cpp where the type is complete.
struct H2State;
void h2_free(H2State* h2);

// assets.hpp owns both (#170). Null = no asset tier; requests never
// pay a lookup they did not configure.
class Assets;
struct AssetEntry;

// RFC 9110 §5.4 allows refusing oversized fields; 8k is the fleet
// convention (nginx, h2o) and bounds one head's work - 431 past it.
inline constexpr size_t kMaxHead = 8192;
// Bodies are skipped at this layer, but skipping is still work; 1 MiB
// bounds it - 413 past it (RFC 9110 §15.5.14).
inline constexpr size_t kMaxBody = 1u << 20;
inline constexpr size_t kMaxHeaders = 64;
// One delivery round's budget (#168, Gebot 18: bounded work per tick):
// a source hands over at most this much per continuation, so a slow
// consumer holds one round's worth of pointers, never a whole file.
inline constexpr size_t kDeliverChunk = 64u * 1024;

// THE WARM BUDGET: at or below this a body is COPIED into the response
// buffer and leaves with its head in one append; above it the body
// becomes a source, handed over as POINTERS a round at a time.
//
// It is one delivery round, which is a structural line rather than a
// tuned one: a body that fits in a single round has nothing to gain
// from being a source - the head would have to leave on its own first
// and there is no second round for that to amortise over.
//
// THE MEASUREMENT THIS REPLACED IS WORTH KEEPING, because it is why
// the number here is not the one the older tree used. That tree put
// the crossover at 4 KiB and this one carried it over, which produced
// a 32 KiB collapse on forgecore (0.22x). The cause was not the
// budget: bodies above it went through splice, and splice was being
// compared against a path that copied TWICE (mapping -> buffer ->
// socket). Against the pointer path it actually loses at every size:
//
//   forgecore, -t4 -c400, splice against the same server without it
//       4 KiB  0.99x    32 KiB  1.01x   256 KiB  0.63x    1 MiB  0.79x
//
// So splice is gone, and what remains is one kernel copy out of the
// mapping - which is also what makes this budget a small number
// rather than a tuning surface.
//
// Settable anyway, because the crossover belongs to the machine and
// the asset mix rather than to this file (#166 folds WM_WARM_BUDGET
// into the config; the env knob is what exists today).
inline constexpr size_t kWarmBudgetDefault = kDeliverChunk;

class Http1 {
 public:
  struct Conn {
    // Head bytes a receive ended in the middle of. Capacity survives
    // clear(): a warm connection allocates nothing. An h2 connection
    // reuses it as its frame buffer.
    std::string carry;
    size_t body_skip = 0;  // Content-Length bytes still owed by the wire
    uint8_t listener = 0;  // which listener accepted - whose app this is
    // Undecided until the first bytes: the client preface upgrades to
    // h2 (RFC 9113 3.4), anything else is h1 forever.
    bool fresh = true;
    H2State* h2 = nullptr;  // allocated on the preface, never before
    // The h1 delivery model's source (#168): null on the fast path -
    // that null IS the model's cost there. Set only while a body
    // larger than one kDeliverChunk is being delivered; more() pulls
    // the next chunk each time the sink drains. h1 is serial, so one
    // source suffices; bytes pipelined behind it wait in the carry.
    const AssetEntry* xfer = nullptr;
    // The transfer's window into the wire body: [xfer_off, xfer_end).
    // A full body is {0, wire_len}; a 206 (#148) is the satisfied
    // range - the SAME machinery walks both.
    size_t xfer_off = 0;
    size_t xfer_end = 0;
    // TCP_MAXSEG, queried once at accept over the ring (#147) and never
    // touched again - see ring.hpp's on_accept/on_setup_mss. 0 = not
    // (yet) known, which reads as "never compress": a unix listener
    // never queries it at all (no MSS behind a stream socket), and the
    // brief window between accept and the query's CQE landing degrades
    // the same way, never the other way - a response built before the
    // answer arrives must not guess "big enough to compress".
    uint32_t mss = 0;
    void reset(uint8_t li) {
      carry.clear();
      body_skip = 0;
      listener = li;
      fresh = true;
      h2_free(h2);
      h2 = nullptr;
      xfer = nullptr;
      xfer_off = 0;
      xfer_end = 0;
      mss = 0;
    }
    void set_mss(uint32_t m) { mss = m; }
    ~Conn() { h2_free(h2); }
  };

  // Builds every response the flow can speak, once, and stamps the
  // date. `res` (with its two flags, readable only where resource.hpp
  // is included) carries the runtime tier: dynamic flow nodes and/or a
  // per-request body. Null = fully konst.
  explicit Http1(const flow::KonstSet& ks = {}, const Resource* res = nullptr,
                 bool dynamic_nodes = false, bool dynamic_body = false,
                 Assets* assets = nullptr);

  // The Ring's per-wake hook: patch the date bytes when the wall-clock
  // second changed. Never runs per request.
  void on_tick();

  // True while this connection still owes bytes the Ring has not been
  // handed yet (#168). The Ring asks BEFORE sending, so a send that
  // has more behind it can carry MSG_MORE instead of putting a small
  // segment on the wire and waiting out the peer's delayed ACK - the
  // stall the previous tree measured at 44.30ms average, 1,118 ->
  // 31,077 req/s once fixed. Const and cheap: two pointer tests.
  bool pending(const Conn& st) const;

  // Feed wire bytes; responses land in sink (the connection's out/next,
  // whichever accumulates). False: the connection ends once everything
  // queued has drained - wire-invalidity paths and Connection: close.
  bool feed(Conn& st, const char* data, size_t len, std::string& sink);

  // What a source hands the Ring for one round (#168: "eine Quelle
  // liefert einen Plan, kein Byte"): POINTERS to bytes that already
  // exist - the deflate stream where it lies in the mapping, the 18
  // framing bytes in the entry table. They leave with whatever is in
  // the sink as ONE sendmsg, so nothing is copied in this process.
  // niov == 0 means the round put its bytes in the sink instead.
  struct Plan {
    struct iovec iov[4] = {};
    unsigned niov = 0;
    size_t iov_len = 0;  // total across iov
  };

  // The delivery model's continuation (#168): the Ring calls this when
  // the connection's sink has fully drained - the one signal BOTH
  // protocols produce (h1 has no window; its only backpressure is the
  // send CQE). h1 hands over the next slice of an active transfer as
  // POINTERS; h2 re-runs the parked-stream flush (WINDOW_UPDATE
  // remains its second trigger, and its DATA payload is copied because
  // it interleaves with other streams). Same contract as feed: false
  // ends the connection once everything queued has drained.
  bool more(Conn& st, std::string& sink, Plan& plan);

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
  // #147: the one place a dynamic 200 body picks identity or gzip.
  // Called only when gzip_ok_ - every other resource never reaches
  // here, and pays nothing beyond that one bool test at the call site.
  void assemble_dynamic(const Conn& st, const flow::ReqFacts& facts, const http::ReqValues& vals,
                        const Resp& prefix_id, const Resp& prefix_gz, bool head_only,
                        std::string& sink);
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];  // every status here came from the tables
  }
  bool fail(Conn& st, uint16_t status, std::string& sink);

  // h2's precomputed response header block - ONLY what never changes
  // (:status, konst content-type, allow), encoded never-indexed so the
  // bytes are connection-independent. Built once by h2_build_block
  // (http2.cpp owns the encoding); per response it costs a 9-byte
  // frame header (stream id + flags) + one memcpy.
  struct H2Block {
    std::string bytes;
  };
  void h2_build_block(H2Block& b, uint16_t status, const std::string* ctype,
                      const std::string* allow);
  // Lane 2: whatever CHANGES goes through ls-hpack's encoder and the
  // connection's dynamic table. Today that is the date (changes per
  // second - one insert per second per connection, a one-byte
  // reference in between); the value tiers (etag, location, ...) join
  // it when they land.
  static bool h2_enc_field(void* enc, unsigned char*& ep, unsigned char* eend,
                           const char* name, size_t nlen, const char* val, size_t vlen);

  // The h2 half (http2.cpp): the same konst/resource machinery
  // answers; only the serialization differs - HPACK + HEADERS/DATA
  // frames into the same sink. Return value = feed's contract.
  bool h2_begin(Conn& st, std::string& sink);
  bool h2_feed(Conn& st, const char* data, size_t len, std::string& sink);
  bool h2_error(Conn& st, uint32_t code, std::string& sink);
  void h2_rst(Conn& st, uint32_t stream_id, uint32_t code, std::string& sink);
  bool h2_dispatch(Conn& st, uint32_t stream_id, bool end_stream, std::string& sink);
  bool h2_answer(Conn& st, uint32_t stream_id, const flow::ReqFacts& facts, bool head_only,
                 std::string& sink);
  void h2_flush_pending(Conn& st, std::string& sink);
  // The asset tier's h2 half (#170): per-entry never-indexed blocks
  // built at setup (the HPACK spelling lives in http2.cpp), answered
  // with the same window/park discipline h2_answer has - only the body
  // is segments over the mapping instead of one buffer.
  void h2_build_asset_blocks(AssetEntry& e);
  void h2_build_asset_shared();
  // win_off/win_end: the answer's window into the wire body - full for
  // 200, the satisfied range for 206 (#148); ignored otherwise.
  bool h2_asset_answer(Conn& st, uint32_t stream_id, const AssetEntry& e, uint16_t status,
                       bool head_only, size_t win_off, size_t win_end, std::string& sink);

  time_t sec_ = 0;
  std::vector<Variants> store_;
  std::array<uint8_t, 600> index_ {};  // status -> store_ slot
  Variants ok_head_;  // 200 for HEAD: the same head, no body bytes
  // Heads up to (not including) Content-Length: the assembly points
  // for per-request bodies (200) and for exceptions answering as the
  // negotiated type (500).
  Variants ok_prefix_;
  Variants err_prefix_;
  // #147: identity always carries the resource's own ok_prefix_; these
  // two exist only for resources where gzip_ok_ is true - a 200 head
  // ending, respectively, in "Vary: Accept-Encoding\r\n" alone
  // (identity was chosen, but the resource DOES vary by coding - RFC
  // 9110 12.5.5) or in "Content-Encoding: gzip\r\nVary: ...\r\n" (gzip
  // was chosen). Prebuilt at construction like every other head; only
  // the body bytes and which of these three prefixes get used are
  // decided per request.
  Variants ok_prefix_vary_;
  Variants ok_prefix_gzip_;
  // #147's setup-time decision, TOR 2: this resource's declared
  // encodings (Resource::gzip_offered) AND its Content-Type both say
  // yes (http::compressible_media_type). False for every resource that
  // never declared encodings_provided, and false whenever it did but
  // the media type table says no - "eine Ressource, die nicht
  // komprimiert, kostet keine Verzweigung" beyond this one bool.
  bool gzip_ok_ = false;
  // One konst vector per method, the method folded in at add_route
  // (B12/B10 never re-compare method strings per request).
  flow::KonstSet konst_;
  const Resource* res_ = nullptr;
  bool dynamic_nodes_ = false;
  bool dynamic_body_ = false;
  bool bound_ = false;  // any runtime tier at all
  // Read once at construction from WM_WARM_BUDGET (see kWarmBudgetDefault).
  size_t warm_budget_ = kWarmBudgetDefault;
  std::string body_;    // the run frame's rendered bytes; capacity survives
  // #147: the gzip encoding of body_ for the current request, when
  // gzip_ok_ chose to compress. Capacity survives across requests like
  // body_ does - a warm connection reusing a resource that compresses
  // every response allocates nothing after the first one.
  std::string gz_body_;
  // h2 blocks, parallel to store_ via index_; h2_err_ is 500 in the
  // negotiated type (the exception path). ONE 200 block serves konst
  // and dynamic bodies alike - h2 has no Content-Length to differ in.
  std::vector<H2Block> h2_store_;
  H2Block h2_err_;
  // Asset-tier refusals for h2: 405 with Allow: GET, HEAD and 406 with
  // Vary - the entry blocks live on the entries themselves.
  H2Block h2_asset405_;
  H2Block h2_asset406_;
  Assets* assets_ = nullptr;
  // The fast lane's DATA half: a whole precomputed DATA frame (header
  // + konst_.body), stream id still zero at its fixed offset (5) -
  // h2_answer patches those 4 bytes and appends the rest untouched.
  // Only valid when !bound_ (konst_.body never varies); bound
  // resources and the 500 exception body vary per request and keep
  // the dynamic DATA path.
  std::string h2_data200_;
  // The current IMF-fixdate value; h1 patches it into prebuilt bytes,
  // h2 encodes it per response (the peer's dynamic table indexes it
  // after the first send).
  char date_[29] = {};
};

}  // namespace webmachine

#endif
