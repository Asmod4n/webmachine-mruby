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
#include "router.hpp"

namespace webmachine {

// The bound resource (resource.hpp owns the definition; Http1 stays
// mruby-free). resource_run answers decision + render inside ONE VM
// frame; resource_exception_begin lends a pending exception's message
// (copy before the next mruby call).
struct Resource;
struct ReqView;
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, const ReqView* req,
                      std::string* body, bool* have_body);
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);

// The websocket half (#175, wsconn.hpp owns both types and every line
// of mruby behind them). This writer only ever holds the two pointers
// and calls these four - it never learns what a websocket resource is,
// exactly as it never learned what a Resource is.
struct WsResource;
struct WsConn;
bool ws_admit(const WsResource* r, std::string& proto, uint16_t& status);
WsConn* ws_open(const WsResource* r);
bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink);
void ws_free(WsConn* c);

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
// #147 Tor 1, revised (Nutzer-Entscheid 2026-08-22): a fixed floor
// replaces the per-connection TCP_MAXSEG query this tree used to make
// at accept. The kernel would not give the answer through the ring at
// all - io_uring_cmd_getsockopt (io_uring/cmd_net.c) hard-refuses
// every level but SOL_SOCKET, confirmed live - and the only bridge
// (IORING_OP_FIXED_FD_INSTALL + getsockopt(2) + close(2), see
// ring.hpp's on_accept history) cost a whole extra ring round-trip of
// latency on every TCP accept, paid before the connection's first
// recv. 1280 is the IPv6 minimum MTU (RFC 8200 §5): the floor every
// path MUST carry, the one a real fleet clamps to in practice (LTE
// behind a VPN). One segment's payload at the narrowest legal MTU
// runs ~1208-1240 bytes (1280 minus IP/TCP headers minus 12 bytes of
// timestamp option), so head+body >= 1280 is safely >= 2 segments on
// EVERY path - compression there can only ever save a packet. On a
// wider path the band between 1280 and the real MSS spends a little
// CPU compressing a response that still fits one segment; that is the
// CHEAP direction to be wrong in, chosen deliberately.
//
// This is NOT a return to kAssumedMss=1460 (commit 7755820, "Measure
// the MSS, never assume one") - that guess erred the EXPENSIVE way,
// overestimating the segment and refusing compression that would have
// saved packets. A floor errs harmlessly (a little wasted CPU, never
// a missed saving); an assumed ceiling erred the other way. The two
// are opposites, not a repeat.
inline constexpr size_t kCompressFloor = 1280;
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

// The router's miss, carried where a route index is carried (#116). A
// miss answers the prebuilt 404 before B13 - before any method test,
// so POST on an unknown path is 404 and never 405.
inline constexpr uint16_t kNoRoute = 0xffff;

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
    // Is this connection's transport packetized (TCP), or a unix
    // stream behind a proxy (#147)? Set once at accept, from the
    // Ring's own listener table - see ring.hpp's on_accept. Replaces
    // the per-connection TCP_MAXSEG query this tree used to make
    // (Nutzer-Entscheid 2026-08-22, #147 Tor 1 revision): a unix
    // listener's answer is always false, the same as before.
    bool packetized = false;
    // Past the 101 this connection is not HTTP any more (#175): every
    // byte goes to the websocket half and nothing here reads a head
    // again. Null is the whole cost for every connection that never
    // upgrades.
    WsConn* ws = nullptr;
    void reset(uint8_t li, bool pkt) {
      carry.clear();
      body_skip = 0;
      listener = li;
      packetized = pkt;
      fresh = true;
      h2_free(h2);
      h2 = nullptr;
      ws_free(ws);
      ws = nullptr;
      xfer = nullptr;
      xfer_off = 0;
      xfer_end = 0;
    }
    ~Conn() {
      h2_free(h2);
      ws_free(ws);
    }
  };

  // ONE APPLICATION as this writer sees it (#116 slice 2): its route
  // table (borrowed - the AppSpec owns it) and its resources, one per
  // route, in the SAME order route.add registered them. The listener
  // this app was bound to is its INDEX in the array handed to the
  // constructor, which is also the index the Ring writes into every
  // connection at accept - that is the whole of "whose connection is
  // this".
  struct AppInput {
    const RouteTable* table = nullptr;
    const Resource* const* resources = nullptr;
    size_t nroutes = 0;
    // The app's websocket routes, its own table (#175) - empty where
    // the app has none, which is one null pointer at the upgrade and
    // nothing anywhere else.
    const RouteTable* ws_table = nullptr;
    const WsResource* const* ws_resources = nullptr;
    size_t ws_nroutes = 0;
  };

  // Builds every response every route of every app can speak, once, and
  // stamps the date. From here on only the 29 date bytes ever change.
  Http1(const AppInput* apps, size_t napps, Assets* assets = nullptr);
  // One app, one listener - the shape everything but a multi-app file
  // has, spelled so a caller with a single table needs no array.
  Http1(const RouteTable& table, const Resource* const* resources, size_t nroutes,
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
  // Defined below, next to the other per-app state; named here because
  // ws_upgrade takes one.
  struct AppSlot;

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
  // h2's precomputed response header block - ONLY what never changes
  // (:status, konst content-type, allow), encoded never-indexed so the
  // bytes are connection-independent. Built once by h2_build_block
  // (http2.cpp owns the encoding); per response it costs a 9-byte
  // frame header (stream id + flags) + one memcpy.
  struct H2Block {
    std::string bytes;
  };

  // ONE ROUTE'S VOICE (#116). The status supply below (store_/index_)
  // stays ONE per app - a 400 is the same bytes whoever was going to
  // answer, and the date patch walks it once. Everything that carries
  // a RESOURCE's own voice - its 200 in every shape, its Allow, its
  // negotiated type, its #147 gzip decision, its h2 blocks - lives
  // here, one per route, and the router's verdict is the only thing
  // that chooses between them. A konst request therefore pays one
  // table walk and then indexes: no allocation, and no branch the
  // single-resource tree did not already have.
  struct Bundle {
    flow::KonstSet konst;
    const Resource* res = nullptr;
    // status -> slot in the SHARED store_. It starts as a copy of the
    // generic table and then points 200 and 405 at this route's own
    // entries, which were appended to that same store_ at setup. That
    // is why a matched request still indexes ONCE, with no status
    // compare and no second table to consult - the multi-resource cut
    // costs setup memory (two arrays of slots per route) and not a
    // single per-request branch. uint16_t, not uint8_t: two slots per
    // route would otherwise cap the app at ~113 routes.
    std::array<uint16_t, 600> index {};
    bool dynamic_body = false;
    bool bound = false;    // any runtime tier at all
    bool gzip_ok = false;  // #147's setup-time decision, see below
    Variants ok_head;      // 200 for HEAD (RFC 9110 9.3.2): head, no body
    // Heads up to (not including) Content-Length: the assembly points
    // for per-request bodies (200) and for exceptions answering as the
    // negotiated type (500).
    Variants ok_prefix;
    // #147: identity always carries the resource's own ok_prefix;
    // these two exist only where gzip_ok is true - a 200 head ending,
    // respectively, in "Vary: Accept-Encoding\r\n" alone (identity was
    // chosen, but the resource DOES vary by coding - RFC 9110 12.5.5)
    // or in "Content-Encoding: gzip\r\nVary: ...\r\n" (gzip was
    // chosen). Prebuilt like every other head; only the body bytes and
    // which of the three prefixes gets used are decided per request.
    Variants ok_prefix_vary;
    Variants ok_prefix_gzip;
    Variants err_prefix;
    H2Block h2_err;  // 500 in the negotiated type (bound routes only)
    // The fast lane's DATA half: a whole precomputed DATA frame
    // (header + konst.body), stream id still zero at its fixed offset
    // (5) - h2_answer patches those 4 bytes and appends the rest
    // untouched. Only valid when !bound (konst.body never varies);
    // bound resources and the 500 exception body vary per request and
    // keep the dynamic DATA path.
    std::string h2_data200;
  };

  // The one setup body both constructors run.
  void build(const AppInput* apps, size_t napps);
  static void build_variants(Variants& v, uint16_t status, const char* extra,
                             const char* body, const char* date);
  void build_status(uint16_t status, const char* extra, const char* body);
  void build_bundle(Bundle& b, const Resource* res);
  static void patch_date(Variants& v, const char* core);
  // prefix + hand-spelled Content-Length + (unless HEAD) the lent body.
  static void assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                       bool head_only);
  // #147: the one place a dynamic 200 body picks identity or gzip.
  // Called only when the route's gzip_ok - every other route never
  // reaches here, and pays nothing beyond that one bool test.
  void assemble_dynamic(const Conn& st, const flow::ReqFacts& facts, const http::ReqValues& vals,
                        const Resp& prefix_id, const Resp& prefix_gz, bool head_only,
                        std::string& sink);
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];  // every status here came from the tables
  }
  bool fail(Conn& st, uint16_t status, std::string& sink);
  // The upgrade (#175): answers 101 (or the refusal the route earned)
  // and switches the connection over. `rest`/`rest_len` are the bytes
  // that came behind the handshake in the same receive - a client that
  // sends its first frame immediately is not made to wait for another
  // packet. False = this connection ends once the sink has drained.
  // `hdrs` is the phr_header array off feed's own frame, passed as
  // void* so this header stays free of picohttpparser (request.cpp is
  // where that shape is known - request.hpp says the same).
  bool ws_upgrade(Conn& st, const AppSlot& slot, int route, const char* path, size_t path_len,
                  const RouteSpans& spans, const char* key, size_t key_len, const void* hdrs,
                  size_t nhdr, const char* rest, size_t rest_len, std::string& sink);

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
  // `route` is the router's verdict for this stream, parked with the
  // facts when a body is still owed; kNoRoute answers the prebuilt 404
  // the miss earned, before B13 and before any method test.
  // `req` is what a runtime callback may ask about this request (#116
  // slice 4), built by the caller because only the caller knows where
  // the bytes are: the live decode buffer for a request answered
  // inside its own dispatch, the stream's own copy for one that
  // parked. Null where no resource can ask (a router miss).
  // A parked request's view, rebuilt from the stream's own copy of the
  // target (http2.cpp says why the spans cannot be parked with it).
  // Null = no route, so nothing can ask.
  const ReqView* h2_parked_view(Conn& st, const std::string& target, ReqView& out);
  bool h2_answer(Conn& st, uint32_t stream_id, const flow::ReqFacts& facts, bool head_only,
                 uint16_t route, const ReqView* req, std::string& sink);
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

  // One app's place in this writer (#116 slice 2): which table its
  // requests walk, and where its bundles start in the ONE bundles_
  // vector. Indexed by the connection's listener - the Ring wrote that
  // number at accept, so the lookup is an array index and never a
  // search. Bundles stay in one vector deliberately: the date patch is
  // then ONE loop per second no matter how many apps a process serves.
  struct AppSlot {
    const RouteTable* table = nullptr;
    uint16_t base = 0;   // first bundle index
    uint16_t count = 0;  // how many (the router's verdict is < count)
    // The websocket table and where this app's websocket resources
    // start in ws_res_ - the same base-plus-verdict shape, for the
    // same reason (#116 slice 2).
    const RouteTable* ws_table = nullptr;
    uint16_t ws_base = 0;
  };

  time_t sec_ = 0;
  // Borrowed route tables, one per listener. ONE walk per request
  // decides which bundle answers; both protocols walk the SAME table of
  // the SAME app in the same order (h1 in feed, h2 in h2_dispatch).
  std::vector<AppSlot> apps_;
  std::vector<Bundle> bundles_;  // every app's routes, back to back
  // Every app's websocket resources, back to back. Borrowed: the
  // AppSpec owns them, like every table here.
  std::vector<const WsResource*> ws_res_;
  // The generic status supply, one per app. It also holds a 200 and a
  // 405 slot, built neutrally so index_ stays total for any status the
  // flow tables can name - a MATCHED route never reads those two (its
  // bundle owns them), and a miss only ever reads 404.
  std::vector<Variants> store_;
  std::array<uint16_t, 600> index_ {};  // status -> store_ slot
  // h2 blocks, parallel to store_ via index_.
  std::vector<H2Block> h2_store_;
  // Asset-tier refusals for h2: 405 with Allow: GET, HEAD and 406 with
  // Vary - the entry blocks live on the entries themselves.
  H2Block h2_asset405_;
  H2Block h2_asset406_;
  Assets* assets_ = nullptr;
  // Read once at construction from WM_WARM_BUDGET (see kWarmBudgetDefault).
  size_t warm_budget_ = kWarmBudgetDefault;
  std::string body_;  // the run frame's rendered bytes; capacity survives
  // #147: the gzip encoding of body_ for the current request, when the
  // route's gzip_ok chose to compress. Capacity survives across
  // requests like body_ does - a warm connection reusing a resource
  // that compresses every response allocates nothing after the first.
  std::string gz_body_;
  // The current IMF-fixdate value; h1 patches it into prebuilt bytes,
  // h2 encodes it per response (the peer's dynamic table indexes it
  // after the first send).
  char date_[29] = {};
};

}  // namespace webmachine

#endif
