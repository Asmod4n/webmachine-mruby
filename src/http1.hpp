//
// The connection layer: the h2 stream and connection state, the
// WebSocket and event-stream carriers, and class Http1, the application
// the reactor drives. The translation units that frame requests read
// this; the others read webmachine.hpp alone, the contract between the
// tiers.
#ifndef WEBMACHINE_HTTP1_HPP
#define WEBMACHINE_HTTP1_HPP

#include "webmachine.hpp"

#include "h2_wire.hpp"

#include <slipstream_tmpfile.h>

namespace webmachine {

struct AssetEntry;

// RFC 9110 6.4: from this size up a request body goes to a file rather
// than into memory. Under it the bytes stay where the framing left them,
// and request.body is a StringIO over a copy.
//
// The number is one response window (kResponseFileWindow), which is what
// this server already calls "more than one read of a file". Below it a
// body is one allocation the carrier reuses; above it the carrier would
// hold every byte of every upload at once, and one client decides how
// many that is.
inline constexpr size_t kBodySpill = 256u * 1024;

// RFC 9110 6.4: a request body that lives in a file. Both protocols use
// it: an h1 connection carries one, an h2 stream carries one each,
// because h2 uploads on many streams at the same time.
//
// slipstream_tmpfile made the file, so it has no name: nothing to clean
// up, and nothing another process can open. `fd` of -1 says this body is
// in memory, which is every body under kBodySpill.
struct BodySpill {
  int fd = -1;
  // What reached the file. It is the body's whole length once the body
  // is complete, and request.body reads that many bytes from offset 0.
  size_t written = 0;
  // Whether a run has taken the file into its request view. Until it
  // has, the file is a body still arriving, and closing it would throw
  // away what the run is about to read.
  bool bound = false;

  // The file goes back. The descriptor holds the last reference to it,
  // so the close frees the blocks - there is no name to unlink.
  void close_file() {
    if (fd < 0) return;
    ::close(fd);
    fd = -1;
    written = 0;
    bound = false;
  }
  // Answers false when the file cannot be made, which is a 500: the
  // request cannot be answered without its body.
  bool open_file() {
    fd = slipstream_tmpfile(nullptr);
    if (mrb_unlikely(fd < 0)) {
      fd = -1;
      return false;
    }
    return true;
  }
  // Take body octets. h1 calls it from feed, h2 from the DATA frame.
  // Answers false when the file refuses the bytes, which is a 500.
  // The file dies with the carrier that holds it, however that carrier
  // ends. A move steals the descriptor and leaves the source at -1, so
  // an H2Stream the stream table moves cannot close a file twice.
  BodySpill() = default;
  ~BodySpill() { close_file(); }
  BodySpill(const BodySpill&) = delete;
  BodySpill& operator=(const BodySpill&) = delete;
  BodySpill(BodySpill&& o) noexcept : fd(o.fd), written(o.written), bound(o.bound) {
    o.fd = -1;
    o.written = 0;
    o.bound = false;
  }
  BodySpill& operator=(BodySpill&& o) noexcept {
    if (this == &o) return *this;
    close_file();
    fd = o.fd;
    written = o.written;
    bound = o.bound;
    o.fd = -1;
    o.written = 0;
    o.bound = false;
    return *this;
  }
  bool take(const char* p, size_t n) {
    while (n != 0) {
      const ssize_t w = ::write(fd, p, n);
      if (w <= 0) {
        if (w < 0 && errno == EINTR) continue;
        return false;
      }
      p += static_cast<size_t>(w);
      n -= static_cast<size_t>(w);
      written += static_cast<size_t>(w);
    }
    return true;
  }
};

// RFC 9113 5.1: one entry per stream in a non-idle state. The fields are
// what that state machine names and nothing else: what the stream has
// received, what it still owes, and whether either half is closed.
struct SseStream;
void sse_free(SseStream* s);
struct WsConn;
void ws_free(WsConn* c);

struct H2Stream {
  // RFC 9113 5.1.1: the Stream Identifier every frame carries.
  uint32_t id = 0;
  // RFC 9113 6.9.1: the stream's half of the flow-control window. Signed
  // because a SETTINGS_INITIAL_WINDOW_SIZE change can drive it negative.
  int64_t flow_window = kH2DefaultWindow;
  // RFC 9110 6.4: the request's content. Counted and kept, because
  // request.body reads it at END_STREAM (RFC 9113 6.1).
  size_t content_received = 0;
  std::string request_content;
  // RFC 9110 6.4: a body of kBodySpill or more, in a file instead of in
  // request_content. One file per stream, because an h2 connection
  // carries many uploads at the same time. The stream table moves an
  // entry when a stream closes, and BodySpill moves with it.
  BodySpill spill;
  // RFC 9110 8.6: what the sender said it would send, and whether it said.
  size_t content_length = 0;
  bool content_length_given = false;
  // RFC 9113 8.3: a parked request is answered after hdrbuf has been
  // reused by the next dispatch, so its fields cannot be lent.
  //
  // They are copied here instead: names and values end to end in
  // `field_blob`, four offsets each in `field_spans`. Only a request
  // that carries a body pays it.
  std::string field_blob;
  std::vector<uint32_t> field_spans;
  flow::ReqFacts facts;
  // RFC 9113 6.9.1: an answer flow control could not frame yet. The asset
  // and its verdict wait here; the byte range is [first, end).
  const AssetEntry* parked_asset = nullptr;
  uint16_t parked_status = 0;
  // RFC 9113 5.1: a run is parked on this stream. The entry stays until
  // the run answers, so a RST_STREAM or a WINDOW_UPDATE for it finds it.
  bool parked = false;
  size_t parked_first = 0;
  size_t parked_end = 0;
  // RFC 9110 6.4: the response content, in one form whatever it is made
  // of. A content this stream owes is a base, a cursor, an end, and -
  // where the base is borrowed - a release obligation; the three sources
  // this replaced differed in nothing else. Carrying them as three
  // parallel triples is what let a release rule live apart from the lend
  // it releases, which is the shape the h1 mapping's use-after-free had.
  struct Content {
    // RFC 9110 8.1: where the representation data comes from.
    enum class Src : uint8_t { kNone, kAsset, kLent, kOwned };
    // kAsset: RFC 1952 framing means one logical range is up to three
    // iovecs (gzip header, the stored deflate payload, trailer), so the
    // entry travels and not a pointer.
    const AssetEntry* asset = nullptr;
    const char* lent = nullptr;  // kLent: the handler's frozen String
    std::string owned;           // kOwned: what flow control could not frame
    // RFC 9113 6.9.1: what has already left, against RFC 9110 8.6's total.
    size_t sent = 0;
    size_t length = 0;
    // No RFC: mruby's GC. Non-null exactly while an unroot is owed, and
    // H2State::content_retire is the one place that clears it, so no
    // value is ever unrooted twice.
    mrb_state* mrb = nullptr;
    mrb_value value = {};
    Src src = Src::kNone;
    // RFC 9113 6.9.1: flow control can cut content across many rounds, so
    // "still owes octets" is what keeps the stream - and the lend - alive.
    bool owes() const { return src != Src::kNone && sent < length; }
    void take_asset(const AssetEntry* e, size_t first, size_t end) {
      src = Src::kAsset;
      asset = e;
      sent = first;
      length = end;
    }
    void take_lent(mrb_state* m, mrb_value v, const char* p, size_t n) {
      src = Src::kLent;
      lent = p;
      sent = 0;
      length = n;
      mrb = m;
      value = v;
    }
    void take_owned(const char* p, size_t n) {
      src = Src::kOwned;
      owned.assign(p, n);
      sent = 0;
      length = n;
    }
    // WHATWG HTML: an event stream hands over its next tick while the
    // stream is still sending the last one. What has left already is
    // dropped from the front, so a stream that runs for hours holds only
    // what the window has not taken yet.
    void append_owned(const char* p, size_t n) {
      if (src != Src::kOwned) {
        take_owned(p, n);
        return;
      }
      if (sent != 0) {
        owned.erase(0, sent);
        length -= sent;
        sent = 0;
      }
      owned.append(p, n);
      length += n;
    }
    void clear() {
      src = Src::kNone;
      asset = nullptr;
      lent = nullptr;
      owned.clear();
      sent = 0;
      length = 0;
    }
  };
  Content response_content;
  // No RFC: this server's route table index.
  uint16_t route = 0;
  // RFC 9113 8.3.1: the :path pseudo-header, which is the request target.
  std::string request_target;
  // RFC 9110 9.3.2: HEAD is GET without content.
  bool head_method = false;
  // RFC 9113 6.2: END_HEADERS has been seen, so the field section is whole.
  bool end_headers = false;
  // RFC 9113 5.1: the peer will send no more DATA on this stream.
  bool half_closed_remote = false;
  // RFC 8441: the WebSocket this h2 stream carries, or nothing. The
  // stream is the transport - its DATA frames hold RFC 6455 frames.
  WsConn* ws = nullptr;
  // WHATWG HTML: the event stream this h2 stream carries, or nothing.
  // One per stream, because an h2 connection multiplexes them - h1 keeps
  // its one on the connection.
  SseStream* sse = nullptr;
  // RFC 9113 6.1: this stream stays open when its content drains. An
  // event stream sends its next tick later, so the last DATA frame of a
  // tick must not carry END_STREAM.
  bool streaming = false;
};

struct H2State {
  struct lshpack_enc enc;
  struct lshpack_dec dec;

  // RFC 9113 6.9.1: the connection's half of the flow-control window.
  int64_t flow_window = kH2DefaultWindow;
  int64_t peer_initial_window = kH2DefaultWindow;
  uint32_t peer_max_frame = kH2MaxFrameSize;
  uint32_t last_stream = 0;
  uint32_t highest_opened = 0;
  size_t flush_cursor = 0;
  bool goaway_sent = false;
  bool goaway_recv = false;

  std::string frag;
  uint32_t frag_stream = 0;
  uint8_t frag_flags = 0;
  bool frag_active = false;

  std::string hdrbuf;

  std::vector<H2Stream> streams;

  // RFC 7541 2.3.3 / 4.1: every insert into the dynamic table shifts the
  // index of everything older by one. A cached head that references an
  // entry is therefore only valid while nothing has been inserted since
  // it was built - and the dynamic path inserts freely (its date, and
  // every field line an app sets). Counted here, compared below: over-
  // counting only costs a rebuild, under-counting would replay an index
  // that has moved.
  uint64_t enc_ins = 0;

  struct {
    std::string bytes;
    size_t head_len = 0;
    uint64_t enc_ins = 0;
    // RFC 7541 6.2.1: the same head, spelled with the insert instead of
    // the reference.
    //
    // A dynamic-table entry has to reach the peer once before anything
    // may point at it. So the response that builds the entry carries
    // this form, and every one after it carries `bytes`.
    std::string prime;
    bool primed = false;
    bool has_data = false;
    uint16_t status = 0;
    uint16_t route = 0xffff;
    time_t sec = 0;
  } head_cache;

  // A body whose last bytes are in the round now on the wire: the stream
  // that owned it is gone, but the writer still points at it, so it waits
  // here for the drained-round point (Http1::Conn::zc_release) instead of
  // being unrooted where the stream ended.
  struct Lend {
    mrb_state* mrb;
    mrb_value v;
  };
  std::vector<Lend> retired;

  // ls-hpack: lshpack_enc_init allocates and returns -1 when it could
  // not - the one call of the four that can fail. Ignoring it left an
  // encoder that was never built, to be handed to lshpack_enc_encode on
  // the first answer. A constructor cannot refuse, so it records, and
  // h2_begin refuses.
  bool hpack_ready = false;
  // RFC 9113: allocated only when the preface was spoken, never before.
  H2State() {
    hpack_ready = lshpack_enc_init(&enc) == 0;
    lshpack_dec_init(&dec);
    lshpack_dec_set_max_capacity(&dec, kH2DecTableSize);
    // ls-hpack leaves the dynamic table's array NULL, and its first
    // growth does memcpy(new, NULL + 0, 0) - undefined, and two UBSan
    // reports on the first h2 request this server ever answers.
    //
    // No caller can avoid it, so the decoder is handed a table instead
    // and that growth never runs. 64 is the size upstream would have
    // chosen, and lshpack_dec_cleanup frees it. A failed malloc leaves
    // things exactly as ls-hpack would have.
    //
    // Pinned at v2.3.5 (cf0f70d). This goes when a release grows the
    // array before its first push.
    if (dec.hpd_dyn_table.els == nullptr) {
      constexpr unsigned kFirstTableSlots = 64;
      void* const mem = std::malloc(kFirstTableSlots * sizeof(uintptr_t));
      if (mem != nullptr) {
        dec.hpd_dyn_table.els = static_cast<uintptr_t*>(mem);
        dec.hpd_dyn_table.nalloc = kFirstTableSlots;
      }
    }
  }
  // RFC 9113: the decoder dies with the connection - and so does every
  // lend the streams still hold. h1's ~Conn, one tier down: unconditional,
  // GOAWAY or error or a client that simply left.
  ~H2State() {
    for (H2Stream& s : streams) content_retire(s);
    content_drain();
    lshpack_enc_cleanup(&enc);
    lshpack_dec_cleanup(&dec);
  }
  H2State(const H2State&) = delete;
  H2State& operator=(const H2State&) = delete;

  // RFC 9113 5.1: a stream in the table is open or half-closed.
  H2Stream* find(uint32_t id) {
    for (H2Stream& st : streams)
      if (st.id == id) return &st;
    return nullptr;
  }
  // RFC 9113 5.1: a stream the connection must remember.
  H2Stream& open(uint32_t id) {
    if (H2Stream* st = find(id)) return *st;
    streams.emplace_back();
    H2Stream& st = streams.back();
    st.id = id;
    st.flow_window = peer_initial_window;
    return st;
  }
  // RFC 9113 5.1: content leaves the stream when the stream does.
  //
  // Clearing `mrb` here makes a second call a no-op, so no value is
  // unrooted twice. The content is cleared whole, so an asset or an
  // owned buffer cannot outlive the stream that framed it.
  void content_retire(H2Stream& s) {
    if (s.response_content.mrb != nullptr) {
      retired.push_back(Lend{s.response_content.mrb, s.response_content.value});
      s.response_content.mrb = nullptr;
    }
    s.response_content.clear();
  }
  // The release: called where a whole round has drained, so nothing the
  // kernel was handed still points into these Strings.
  void content_drain() {
    for (const Lend& l : retired) resource_body_unlend(l.mrb, l.v);
    retired.clear();
  }
  // RFC 9113 5.1: the number stays, the entry goes.
  void close_stream(uint32_t id) {
    for (size_t i = 0; i < streams.size(); i++) {
      if (streams[i].id == id) {
        // The move-assign below discards this entry's members: a body it
        // still holds has to leave first, or its root leaks silently on
        // every close - RST_STREAM, END_STREAM and error paths alike.
        content_retire(streams[i]);
        // WHATWG HTML: the resource hears that its stream ended, once,
        // however it ended.
        if (streams[i].sse != nullptr) {
          sse_free(streams[i].sse);
          streams[i].sse = nullptr;
        }
        // RFC 6455 7: and the same for a WebSocket, which hears on_close.
        if (streams[i].ws != nullptr) {
          ws_free(streams[i].ws);
          streams[i].ws = nullptr;
        }
        streams[i] = std::move(streams.back());
        streams.pop_back();
        return;
      }
    }
  }
};
}

namespace webmachine {
namespace wsdeflate {
inline constexpr uint8_t kMinRawWindowBits = 9;

inline constexpr unsigned char kSyncTail[4] = {0x00, 0x00, 0xff, 0xff};

struct Params {
  bool on = false;
  bool server_no_context_takeover = false;
  bool client_no_context_takeover = false;
  uint8_t server_max_window_bits = 15;
  uint8_t client_max_window_bits = 15;
};

namespace detail {
// RFC 9110 5.6.3: optional whitespace.
constexpr bool is_ows(char c) { return c == ' ' || c == '\t'; }

// RFC 9110 5.6.2: token, which is what 7692 4.2's params are.
constexpr bool is_tchar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
         c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' ||
         c == '~';
}

// RFC 9110 5.1: case-insensitive equality for an extension parameter name.
inline bool ci_eq(std::string_view text, std::string_view lit) {
  const char* const s = text.data();
  const size_t n = text.size();
  const size_t litn = lit.size();
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// RFC 7692 7.1.2.1: 8..15, no leading zeroes - "08" is a refusal.
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
}

// RFC 7692 4.2/5.1: one Sec-WebSocket-Extensions value, answered with the
// first offer this endpoint can accept. Declining is never an error.
// What one negotiation answers: the parameters this endpoint accepted, and
// the Sec-WebSocket-Extensions value to echo back.
struct Negotiated {
  Params& params;
  std::string& echo;
};

inline bool negotiate(std::string_view value, Negotiated out) {
  const char* const v = value.data();
  const size_t len = value.size();
  size_t i = 0;
  while (i < len) {
    while (i < len && (detail::is_ows(v[i]) || v[i] == ',')) i++;
    const size_t name_at = i;
    while (i < len && detail::is_tchar(v[i])) i++;
    const size_t name_len = i - name_at;
    bool ok = detail::ci_eq({v + name_at, name_len}, "permessage-deflate");

    Params p;
    p.on = true;
    bool seen_snct = false, seen_cnct = false, seen_smwb = false, seen_cmwb = false;
    bool echo_cmwb = false;

    while (true) {
      while (i < len && detail::is_ows(v[i])) i++;
      if (i >= len || v[i] != ';') break;
      i++;
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
          i++;
          pv = v + i;
          while (i < len && v[i] != '"') {
            if (v[i] == '\\' && i + 1 < len) i++;
            i++;
          }
          pv_len = static_cast<size_t>(v + i - pv);
          if (i < len) i++;
        } else {
          pv = v + i;
          while (i < len && detail::is_tchar(v[i])) i++;
          pv_len = static_cast<size_t>(v + i - pv);
        }
      }
      if (!ok) continue;

      if (detail::ci_eq({v + pn_at, pn_len}, "server_no_context_takeover")) {
        if (seen_snct || have_value) { ok = false; continue; }
        seen_snct = true;
        p.server_no_context_takeover = true;
      } else if (detail::ci_eq({v + pn_at, pn_len}, "client_no_context_takeover")) {
        if (seen_cnct || have_value) { ok = false; continue; }
        seen_cnct = true;
        p.client_no_context_takeover = true;
      } else if (detail::ci_eq({v + pn_at, pn_len}, "server_max_window_bits")) {
        uint8_t b = 0;
        if (seen_smwb || !have_value || !detail::window_bits(pv, pv_len, b) ||
            b < kMinRawWindowBits) {
          ok = false;
          continue;
        }
        seen_smwb = true;
        p.server_max_window_bits = b;
      } else if (detail::ci_eq({v + pn_at, pn_len}, "client_max_window_bits")) {
        if (seen_cmwb) { ok = false; continue; }
        seen_cmwb = true;
        if (have_value) {
          uint8_t b = 0;
          if (!detail::window_bits(pv, pv_len, b)) { ok = false; continue; }
          p.client_max_window_bits = b;
          echo_cmwb = true;
        }
      } else {
        ok = false;
      }
    }

    if (ok) {
      out.params = p;
      out.echo.assign("permessage-deflate");
      if (p.server_no_context_takeover) out.echo.append("; server_no_context_takeover");
      if (p.client_no_context_takeover) out.echo.append("; client_no_context_takeover");
      if (seen_smwb) {
        out.echo.append("; server_max_window_bits=")
            .append(std::to_string(static_cast<unsigned>(p.server_max_window_bits)));
      }
      if (echo_cmwb) {
        out.echo.append("; client_max_window_bits=")
            .append(std::to_string(static_cast<unsigned>(p.client_max_window_bits)));
      }
      return true;
    }
    while (i < len && v[i] != ',') i++;
  }
  return false;
}
// RFC 7692 7: the codec itself lives in wsconn.cpp - it is the only
// file that codes a frame. Params and negotiate stay here because the
// h1 upgrade path negotiates the extension before a WsConn exists.
class Codec;
}
}

namespace webmachine {
inline constexpr size_t kMaxWsMessageDefault = 64u * 1024;

struct WsConn;

bool ws_wants_deflate(const WsResource* r);

// RFC 6455 4.2.2: what admitting one connection answered - the subprotocol
// to echo back, and the status a refusal carries (0 = admitted).
struct WsAdmit {
  std::string& proto;
  uint16_t& status;
};
WsConn* ws_admit(const WsResource* r, Logger* elog, WsAdmit out);

void ws_open(WsConn* c, const wsdeflate::Params& deflate);

bool ws_feed(WsConn* c, std::string_view data, std::string& sink);

void ws_free(WsConn* c);
}

namespace webmachine {
struct SseStream;

SseStream* sse_open(const SseResource* r, Logger* log, uint16_t& code);

bool sse_second(SseStream* s, int64_t now_s, std::string& sink);
// WHATWG HTML: the same tick, unframed - what the resource said. h2 puts
// these bytes in DATA frames instead of a chunk.
bool sse_tick(SseStream* s, int64_t now_s, std::string& body);

void sse_free(SseStream* s);
}

namespace webmachine {
namespace ws {
enum : uint8_t {
  kContinuation = 0x0,
  kText = 0x1,
  kBinary = 0x2,
  kClose = 0x8,
  kPing = 0x9,
  kPong = 0xa,
};

enum : uint16_t {
  kCloseNormal = 1000,
  kCloseGoingAway = 1001,
  kCloseProtocolError = 1002,
  kCloseUnsupportedData = 1003,
  kCloseInvalidPayload = 1007,
  kClosePolicyViolation = 1008,
  kCloseTooBig = 1009,
  kCloseInternalError = 1011,
};

inline constexpr size_t kMaxControlPayload = 125;

bool accept_key(const char* key, size_t key_len, char out[28]);

// RFC 6455 5.2: everything the fourteen header bytes decide on their own -
// the reserved bits, the opcode, the mask bit, the length encoding, and
// what a control frame may not be. Pure, because begin_frame used to judge
// these one at a time while already writing the refusal for the first one
// that failed, and because these are the Autobahn cases: they deserve a
// table, not a socket.
struct Head {
  // No RFC: our verdict on the header, which 6455 5.1 turns into a close.
  enum class Err : uint8_t { kNone, kProtocol, kTooBig };
  Err err = Err::kNone;
  uint8_t opcode = 0;           // RFC 6455 5.2: Opcode
  uint64_t payload_length = 0;  // RFC 6455 5.2: Payload length
  // RFC 6455 5.2: where the four Masking-key octets start, which is where
  // the length encoding ended.
  uint8_t masking_key_at = 0;
  bool fin = false;   // RFC 6455 5.2: FIN
  bool rsv1 = false;  // RFC 6455 5.2: RSV1, negotiated by RFC 7692
  bool control = false;  // RFC 6455 5.5: opcode has the high bit
};

// RFC 6455 5.2: how many header octets the next decision needs, given how
// many have arrived. Two to see the length encoding and the mask bit, then
// two or eight more for an extended Payload length, then four for the
// Masking-key. Pure and here, not in the reader, because read_head reads
// all of them unconditionally - so this is the one thing that has to be
// true before read_head may be called at all.
inline uint8_t header_need(const unsigned char* h, uint8_t have) {
  if (have < 2) return 2;
  const uint8_t len7 = static_cast<uint8_t>(h[1] & 0x7f);
  const uint8_t ext = len7 == 126 ? 2 : (len7 == 127 ? 8 : 0);
  return static_cast<uint8_t>(2 + ext + ((h[1] & 0x80) != 0 ? 4 : 0));
}

// RFC 6455 5.3: transformed-octet-i = original-octet-i XOR
// masking-key-octet-(i MOD 4).
//
// It copies rather than unmasking in place, because every caller is
// already moving the octets somewhere - the control buffer, the inflate
// window, a test's own buffer - so both happen in one pass.
// `key_at` is i's offset within the frame, so a payload delivered in
// pieces keeps the key aligned across recvs.
struct Mask {
  const unsigned char* key;  // the frame's four masking octets
  size_t at;                 // how far into the frame the next octet sits
};

inline void unmask_copy(char* dst, std::string_view src, Mask m) {
  for (size_t i = 0; i < src.size(); i++) {
    dst[i] = static_cast<char>(src[i] ^ m.key[(m.at + i) & 3]);
  }
}

inline Head read_head(const unsigned char* h, bool have_codec) {
  Head o;
  const unsigned char b0 = h[0];
  const unsigned char b1 = h[1];
  o.fin = (b0 & 0x80) != 0;
  o.rsv1 = (b0 & 0x40) != 0;
  o.opcode = static_cast<uint8_t>(b0 & 0x0f);
  o.control = (o.opcode & 0x08) != 0;
  // RFC 6455 5.2: RSV2 and RSV3 are never negotiated here, and RSV1 only
  // where a codec was.
  if ((b0 & 0x30) != 0) { o.err = Head::Err::kProtocol; return o; }
  if (o.rsv1 && !have_codec) { o.err = Head::Err::kProtocol; return o; }
  switch (o.opcode) {
    case kContinuation:
    case kText:
    case kBinary:
    case kClose:
    case kPing:
    case kPong: break;
    default: o.err = Head::Err::kProtocol; return o;
  }
  // RFC 7692 6: the per-message bit rides the first frame of a data
  // message and nothing else.
  if (o.rsv1 && (o.control || o.opcode == kContinuation)) {
    o.err = Head::Err::kProtocol;
    return o;
  }
  // RFC 6455 5.1: every client frame is masked.
  if ((b1 & 0x80) == 0) { o.err = Head::Err::kProtocol; return o; }
  o.payload_length = static_cast<uint64_t>(b1 & 0x7f);
  o.masking_key_at = 2;
  // RFC 6455 5.2: the shortest encoding that fits, and the top bit of a
  // 64-bit length is reserved.
  if (o.payload_length == 126) {
    o.payload_length = (static_cast<uint64_t>(h[2]) << 8) | h[3];
    o.masking_key_at = 4;
    if (o.payload_length < 126) { o.err = Head::Err::kProtocol; return o; }
  } else if (o.payload_length == 127) {
    o.payload_length = 0;
    for (int i = 0; i < 8; i++) o.payload_length = (o.payload_length << 8) | h[2 + i];
    o.masking_key_at = 10;
    if (o.payload_length <= 0xffff || (o.payload_length >> 63) != 0) { o.err = Head::Err::kProtocol; return o; }
  }
  // RFC 6455 5.5: a control frame is short and never fragmented.
  if (o.control && (o.payload_length > kMaxControlPayload || !o.fin)) {
    o.err = Head::Err::kProtocol;
    return o;
  }
  return o;
}

// RFC 6455 5.4: the message a frame would join - the opcode it started
// with (0 = nothing in flight), whether it was negotiated deflated, how
// many octets of it have arrived, and the ceiling this connection allows.
struct Message {
  uint8_t op;
  bool deflated;
  uint64_t len;
  uint64_t max;
};

// RFC 6455 5.4 and 7.4.1: may this frame join it? Four scalars are all the
// connection state that decides it - which is why it can be a table too.
inline Head::Err admit(const Head& h, const Message& msg) {
  const uint8_t msg_op = msg.op;
  const bool msg_deflated = msg.deflated;
  const uint64_t msg_len = msg.len;
  const uint64_t max_message = msg.max;
  if (h.control) return Head::Err::kNone;
  if (h.opcode == kContinuation) {
    if (msg_op == 0) return Head::Err::kProtocol;  // continues nothing
    // A deflated message is bounded after inflation, not here.
    if (!msg_deflated && msg_len + h.payload_length > max_message) return Head::Err::kTooBig;
    return Head::Err::kNone;
  }
  if (msg_op != 0) return Head::Err::kProtocol;  // interleaved data frames
  if (!h.rsv1 && h.payload_length > max_message) return Head::Err::kTooBig;
  return Head::Err::kNone;
}

// RFC 6455 5.2: what a server frame header says.
struct Frame {
  uint8_t opcode;
  bool fin;
  bool rsv1;
  size_t payload_len;
};
size_t build_header(Frame f, char head[10]);

// RFC 6455 5.5.1: what a Close frame said - the code, and the reason where
// it carried one. 1005 is "the peer named none".
struct Close {
  uint16_t code = 1005;
  std::string_view reason;
};
size_t build_close_payload(Close close, char out[125]);
bool read_close(std::string_view payload, Close& out);
}
}

namespace webmachine {
struct WsResource;
struct WsConn;
namespace wsdeflate { struct Params; }
WsConn* ws_admit(const WsResource* r, Logger* elog, WsAdmit out);
bool ws_wants_deflate(const WsResource* r);
void ws_open(WsConn* c, const wsdeflate::Params& deflate);
bool ws_feed(WsConn* c, std::string_view data, std::string& sink);
void ws_free(WsConn* c);

struct SseResource;
struct SseStream;
SseStream* sse_open(const SseResource* r, Logger* log, uint16_t& code);
bool sse_second(SseStream* s, int64_t now_s, std::string& sink);
// WHATWG HTML: the same tick, unframed - what the resource said. h2 puts
// these bytes in DATA frames instead of a chunk.
bool sse_tick(SseStream* s, int64_t now_s, std::string& body);
void sse_free(SseStream* s);

struct H2State;
void h2_free(H2State* h2);

class Assets;
struct AssetEntry;

// #210: the one path the error assets answer under. Reserved, so an
// operator's own tree can never collide with it.
inline constexpr char kErrorAssetsPrefix[] = "/error_assets/";
inline constexpr size_t kErrorAssetsPrefixLen = sizeof(kErrorAssetsPrefix) - 1;
inline constexpr size_t kMaxHeaders = 64;
static_assert(kMaxHeaders <= 255, "http::NamedFieldIndex::at holds a field's place in one byte");
inline constexpr size_t kCompressFloor = 1280;
inline constexpr size_t kDeliverChunk = 64u * 1024;

// response.file reads a window at a time, the way the asset tier already
// delivers (see Http1::more's st.xfer arm), so per-connection memory is
// O(window) and not O(file). A file smaller than this is still one read and
// one round, exactly as before; a larger one is refilled per drained round.
// There is no ceiling on the file itself any more.
// Where a response.file transfer stands. One field, five values: the
// combinations three separate bools could spell - and did spell wrongly -
// are not representable. kDone is the state that made the difference: the
// last lend is on the wire, so the mapping may not be handed back yet, and
// the drained round after it is the one that cleans up.
enum class FileStage : uint8_t { kNone, kNamed, kRing, kDeliver, kDone };

// What the next round of a transfer does. Computed by file_step() from a
// snapshot and by nothing else; applied by file_apply() and by nothing
// else. A POD returned in registers - purity here is about the decision,
// never about the bytes, which stay exactly where they are.
// No RFC - a round of delivery is this server's decision, not HTTP's. The
// quantities it decides about are HTTP's, and it shares three names with
// its h2 twin H2SendStep on purpose: start, give and the fact that a round
// is measured in bytes offered, not bytes owned.
struct FileStep {
  // The source is named, not pointed at - the same shape H2SendStep uses,
  // and for the same reason: a round is a decision about which bytes, and
  // an address is an answer to a different question.
  enum class Src : uint8_t { kNone, kWindow, kMapping };
  Src src = Src::kNone;
  size_t start = 0;       // RFC 9110 6.4: first byte of the content this
                          // round lends
  size_t give = 0;        // how many - the same word H2SendStep uses
  size_t sent_after = 0;  // RFC 9110 8.6: content_sent once it lands
  FileStage next = FileStage::kNone;
  bool head = false;         // RFC 9112 2.1: rides the first round only
  bool release_map = false;  // munmap: off the wire, may go back
  bool log = false;          // the one access line of this transfer
  bool clear = false;        // the transfer is over
  bool persist = true;       // RFC 9112 9.3
};

// The most a mapping lends to one send. The kernel caps a single sendmsg
// at MAX_RW_COUNT (INT_MAX rounded down to a page), and a body offered past
// that comes back short - which reads exactly like a dead peer and drops a
// healthy connection. 64 MiB sits under that cap at every page size, costs
// one extra SQE per 64 MiB and not one extra copy, and bounds how long a
// single operation can hold the connection.
// The slowest client this tier will serve a large file to, in bytes per
// second. 16 kbit/s: half the slowest throttle a mobile network applies once
// a monthly allowance is spent - Vodafone and O2 drop to 32 kbit/s, Telekom
// to 64, and 128 kbit/s is the common US figure. Half, because the send
// deadline is refreshed per completed send, so a client running at exactly
// the chunk's own rate would finish it exactly on the deadline.
inline constexpr size_t kSlowClientRate = 2000;
// A send is bounded at both ends. Below: enough for a frame and its head, so
// a very short send_timeout cannot chop the wire into nothing. Above: one
// sendmsg moves at most MAX_RW_COUNT (INT_MAX rounded down to a page), and a
// body offered past that comes back short - indistinguishable from a dead
// peer.
inline constexpr size_t kFileSendChunkMin = 4096;
inline constexpr size_t kFileSendChunkMax = 64u * 1024 * 1024;

// What one send may carry, from the send timeout and the slowest client
// we serve. At the default 60 s this is 120,000 bytes.
//
// Derived, not chosen. The same number bounds the kernel call and
// decides who is dropped mid-download, so choosing it for one of those
// reasons sets the other in silence.
inline constexpr size_t file_send_chunk(int send_timeout_s) {
  const size_t want =
      static_cast<size_t>(send_timeout_s > 0 ? send_timeout_s : 60) * kSlowClientRate;
  if (want < kFileSendChunkMin) return kFileSendChunkMin;
  if (want > kFileSendChunkMax) return kFileSendChunkMax;
  return want;
}

inline constexpr uint16_t kNoRoute = 0xffff;

class Http1 {
 public:
  // One of these per connection, so the order is by alignment and not by
  // topic: interleaving the flags with the pointers cost 34 bytes of
  // padding in 176, which is a cache line every five connections spent
  // on nothing. Widest first, the single-byte members last and together.
  struct Plan;

  // #80: a bound run that can stop. Only a resource that declared a
  // promise or a watch is called through one, so a run that can never
  // stop pays no frame for the ability.
  //
  // A stopped run has to keep what it borrowed. `view`, `method`, `path`
  // and every field in ReqValues point into a provided buffer, and
  // on_recv gives that buffer back to the kernel before anything
  // resumes. So the bytes are copied, and this frame holds the copy.
  //
  // The head and the body are held separately: a head is a few hundred
  // bytes, a body may be a megabyte, and a body will later be spilled
  // to an O_TMPFILE that only a read makes addressable.
  struct Run {
    struct promise_type;
    using handle = std::coroutine_handle<promise_type>;

    struct promise_type {
      // RFC 9110 15: what the run answered, once it has.
      uint16_t status = 0;
      bool finished = false;
      // Where the answer goes when the run resumes, and why the body may
      // not capture them: the plan of the round that started it lived in
      // on_recv's frame and is gone, and the sink may have swapped
      // (out/next) while the run was stopped. The resumer sets these
      // before resume(), and everything after a stop reads them through
      // here rather than through a reference the frame is holding.
      std::string* sink = nullptr;
      struct Plan* plan = nullptr;
      // RFC 9112 9.3: whether the connection lives past this answer. The
      // round decided it before the run started; `spell_next_round` returns it.
      bool persist = true;
      // #30: which park slot this run took, or -1. The promise is the
      // run's own header, and the resumer reads it there - a connection
      // holds many parked runs and none of them is "the" one.
      int park = -1;

      Run get_return_object() { return Run{handle::from_promise(*this)}; }
      // Runs eagerly: a run that never stops must reach its answer inside
      // the call that started it, exactly as resource_run does today.
      std::suspend_never initial_suspend() noexcept { return {}; }
      // Suspends at the end so the caller can read `status` off the frame
      // and destroy it deliberately - a self-destroying coroutine would
      // take the answer with it.
      std::suspend_always final_suspend() noexcept { return {}; }
      void return_value(uint16_t s) {
        status = s;
        finished = true;
      }
      // A raise is a C++ throw here, and the run frames above already
      // catch it. Rethrowing leaves this frame suspended at
      // its final point, which is where the caller destroys it.
      void unhandled_exception() { throw; }
    };

    Run() = default;
    explicit Run(handle h) : co(h) {}
    Run(const Run&) = delete;
    Run& operator=(const Run&) = delete;
    Run(Run&& o) noexcept : co(o.co) { o.co = {}; }
    Run& operator=(Run&& o) noexcept {
      if (this != &o) {
        destroy();
        co = o.co;
        o.co = {};
      }
      return *this;
    }
    ~Run() { destroy(); }

    // Did it reach an answer, or is it parked on something?
    bool done() const { return !co || co.promise().finished; }
    uint16_t status() const { return co ? co.promise().status : 0; }
    void destroy() {
      if (co) co.destroy();
      co = {};
    }
    // Handed to whatever will resume it - the reactor keeps this and
    // nothing else, because the handle is the parked run's name. There is
    // no slot table and no tag field to translate.
    handle release() {
      const handle h = co;
      co = {};
      return h;
    }

    handle co{};
  };

  // #80: the stop itself. It always suspends, and hands back the run's
  // own promise on the way in.
  //
  // The sink and the plan it writes into belong to the round that
  // resumed it, not to the one that started it. The resumer sets them
  // just before resume(), so the promise is the only way to reach the
  // right ones - a reference captured before the stop would name a sink
  // that is gone.
  struct Park {
    Run::promise_type* p = nullptr;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(Run::handle h) noexcept {
      p = &h.promise();
      return true;
    }
    Run::promise_type& await_resume() const noexcept { return *p; }
  };

  // The same door, held open. A coroutine cannot name its own promise,
  // and the run has to write into it before it ever stops: `persist` is
  // the request's answer and the caller reads it off the frame. So this
  // asks for the promise and refuses to suspend - await_suspend saying
  // false means "carry on", which is the standard way to read your own
  // frame without leaving it.
  struct Self {
    Run::promise_type* p = nullptr;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(Run::handle h) noexcept {
      p = &h.promise();
      return false;
    }
    Run::promise_type& await_resume() const noexcept { return *p; }
  };

  struct Conn {
    // No RFC: octets received and not yet parsed. The name is this
    // server's; RFC 9112 2 has no word for a parser's leftover.
    std::string carry;
    size_t content_skip = 0;
    // RFC 9110 6.4: what a bound route's request body still owes -
    // the bytes themselves collect in `carry` behind the head, which
    // keeps the hand-off zero-copy. A konst route keeps skipping.
    size_t content_need = 0;
    // RFC 9110 6.4: a body under kBodySpill, while the run that asked
    // for it waits. It cannot stay in `carry`: the run already read its
    // head from there, and a pipelined request behind it wants that
    // buffer. A body of kBodySpill or more is in `spill` instead.
    std::string body_hold;
    // #36: a run of this connection stopped at kN11, kO14 or kP3 and
    // waits for the rest of the body. The last octet makes its round
    // ready, and spell_next_round resumes it.
    bool run_wants_body = false;
    // RFC 9110 6.4: a body of kBodySpill or more, in a file instead of
    // in the carry. The file is this connection's, because h1 answers
    // one request at a time.
    BodySpill spill;
    // No RFC: a half-open span into the wire body of an asset (see
    // Assets::wire_iov), not into the file - a gzip member's octets are
    // not the stored ones.
    size_t asset_off = 0;
    size_t asset_end = 0;
    // A lent body splits the sink, so the segments around it carry offsets
    // the plan has to claim explicitly: `zc_covered` is how far it got.
    size_t zc_covered = 0;
    H2State* h2 = nullptr;
    const AssetEntry* asset = nullptr;
    WsConn* ws = nullptr;
    SseStream* sse = nullptr;
    const void* peer = nullptr;
    // No RFC and not the kernel's: "zc" here is the [tune] knob's word,
    // zero_copy_threshold, and it means lent instead of copied - a dynamic
    // body frozen and rooted from the handler's return until the round it
    // belongs to has drained. It is not IORING_OP_SEND_ZC; this tree does
    // not use that opcode anywhere.
    mrb_state* zc_mrb = nullptr;
    mrb_value zc_value = {};
    // #80: the run this connection stopped, if it stopped one. The handle
    // is its name - there is no slot table and no id to look it up by,
    // which is what the scaffolding this replaces was reaching for.
    Run parked;
    // #30: the runs an h2 connection stopped, one per stream. h1 has the
    // one above, because RFC 9112 9.3.2 lets it stop only one.
    struct H2Parked {
      uint32_t stream_id = 0;
      Run run;
    };
    std::vector<H2Parked> h2_parked;

    // The width of one value round: an ETag, a Last-Modified, an
    // Expires and a body. Nothing in the flow asks for a fifth.
    static constexpr int kJobSlots = kValueJobs;
    // Is a run stopped on this connection? Nothing else may speak for it
    // while one is - not the carry behind it, and not a pipelined request
    // (RFC 9112 9.3.2: responses go out in the order the requests came).
    bool run_parked() const { return static_cast<bool>(parked.co) && !parked.done(); }

    // #30: everything one stopped run waits on.
    //
    // A struct of its own because a connection can hold more than one.
    // h1 holds a single stopped run, since RFC 9112 9.3.2 puts the
    // answers out in the order the requests came. An h2 connection
    // multiplexes, and every stream that stops is a run with its own
    // jobs, watchers and answers.
    struct Round {
      // #80: what the worker said, in this VM's values. The reactor puts
      // it here on the way in and the resumed walk reads it once. It is
      // rooted while it waits - nothing on the VM's stack names it.
      //
      // #30: one answer per job. A value round starts several jobs at
      // once - the flow says generate_etag, last_modified and the body
      // render do not decide anything for each other - so the channel is
      // as wide as the round. Slot 0 is the single job's, and a
      // watcher's.
      mrb_value answer_value[kJobSlots] = {};
      // Every job of the round answered; the resume is where the run
      // picks that up, because that is the one point at which a fresh
      // sink and a fresh plan exist to write into.
      bool answer_ready = false;
      // #80: the work a stopped run left, already across. The frame does
      // the crossing itself, at the stop, because that is the last
      // moment the reactor's VM and the run's own state are both to
      // hand - the frame takes that state with it one line later.
      struct Job {
        unsigned code = 0;
        std::string bytes;
        double deadline = 0.0;
        // #30: response.userdata as CBOR, or empty when the run put
        // nothing there. Every job of a round gets the same bytes.
        std::string user_bytes;
        // The reactor has not armed this one yet.
        bool waiting = false;
      };
      Job job[kJobSlots];
      // Which value each job of the round answers - kJobNode for a
      // node's own callback. A watcher fills its place here too, and it
      // has no Job: nothing crosses to a worker for it.
      uint8_t job_what[kJobSlots] = {};
      // #30: response.userdata as the worker left it, per job, when the
      // worker changed it. Rooted like an answer, read at the resume.
      mrb_value user_value[kJobSlots] = {};
      bool user_have[kJobSlots] = {};
      // How many jobs this stop handed over, and how many answered. The
      // run goes on when the two are equal.
      uint8_t jobs_owed = 0;
      // #36: this round's run stopped at a node that reads content, and
      // the body is still arriving. Nothing was handed to a worker or
      // to the ring - the connection makes the round ready when the
      // last octet lands.
      bool wants_body = false;
      uint8_t jobs_answered = 0;
      // Whose VM the answer is decoded back into. It outlives the
      // crossing, because the answer comes long after.
      const Resource* job_res = nullptr;
      // #30: the watcher slot each job of this round waits on, or -1.
      int w_slot[kValueJobs] = {-1, -1, -1, -1};
      // The pool had no slot: load, and load passes. 429 with a
      // Retry-After of a few seconds.
      bool compute_task_full = false;
      // The worker ended the task at its max_runtime. Not load: a second
      // attempt costs the same, so 500 and no Retry-After.
      bool compute_task_over_deadline = false;
      // The worker raised. The registry holds what dies - a database, a
      // connection - so 503 with a Retry-After of a minute.
      bool compute_task_raised = false;
    };
    // #30: where each stopped run of this connection keeps what it
    // waits on. The Round itself lives in the coroutine frame of that
    // run - the frame holds everything about it and stays alive while
    // it waits - and this table is only what the reactor needs: an
    // answer arrives as a completion, and a completion carries a
    // number, not an address.
    //
    // Four bits of the tag name the park slot and four name the job, so
    // one byte carries both and the layout is unchanged.
    static constexpr int kParkSlots = 16;
    Round* park[kParkSlots] = {};
    // Sixteen slots is sixteen bits, so both questions the reactor asks
    // are one instruction: which slots are taken, and which of them owe
    // the reactor an arming. A free slot is the first zero of `taken`,
    // and the next round to arm is the first one of `owes` - both
    // through ctz. The list this replaced was walked to add a slot, to
    // find one and to erase one, and it allocated.
    uint16_t park_taken = 0;
    uint16_t park_owes = 0;
    // #80: which taking of the slot a tag names. A round refused halfway
    // leaves earlier jobs in flight, and the next run on this connection
    // takes the same slot; their answers carry this number, and one
    // that names a taking that ended is dropped.
    uint8_t park_gen[kParkSlots] = {};
    void park_wants_arming(int slot) {
      if (slot < 0 || slot >= kParkSlots) return;
      park_owes |= static_cast<uint16_t>(1u << slot);
    }

    // A slot for a run that is stopping, or -1 when this connection
    // holds as many as a tag can name.
    int park_take(Round* r) {
      if (park_taken == 0xffffu) return -1;
      const int i = __builtin_ctz(static_cast<unsigned>(~park_taken) & 0xffffu);
      park_taken |= static_cast<uint16_t>(1u << i);
      park[i] = r;
      park_gen[i]++;
      return i;
    }
    void park_drop(int slot) {
      if (slot < 0 || slot >= kParkSlots) return;
      park[slot] = nullptr;
      const uint16_t bit = static_cast<uint16_t>(1u << slot);
      park_taken &= static_cast<uint16_t>(~bit);
      park_owes &= static_cast<uint16_t>(~bit);
    }
    Round* park_at(int slot) const {
      if (slot < 0 || slot >= kParkSlots) return nullptr;
      return park[slot];
    }
    // #30: every watcher this connection is running, keyed by the
    // watcher's own mrb_obj_id - nothing is invented to name them with.
    //
    // It is an mruby Hash and not a C++ map because these are Ruby
    // objects: a watcher nobody holds is collected, and with it the
    // source and block it keeps alive. One gc_register roots the hash
    // and the hash roots them all, instead of one registration each.
    //
    // The connection is the right owner because the watchers die with
    // it, and a completion arriving late for a connection already gone
    // is discarded by the generation guard every other op relies on -
    // `!c.live || c.gen != gen`. So nothing here counts anything, and
    // no removal has to be waited for.
    mrb_state* w_mrb = nullptr;
    mrb_value w_hash = {};
    // Added but not yet on the ring. Http1 cannot arm anything - it has
    // no ring - so it leaves the slot here and the reactor collects it,
    // the same way response.file leaves a path for arm_file_open.
    std::vector<int> w_pending;
    uint8_t listener = 0;
    uint8_t peer_len = 0;   // no RFC: the socket's address, already spelled
    bool fresh = true;
    bool packetized = false;
    bool zc_lent = false;   // a lend is outstanding right now
    bool zc_split = false;
    // response.file: the answer a run deferred to the reactor. `want` = the
    // open is owed, `busy` = the ring is on it, `ready` = the head is
    // spelled and `spell_next_round` may put it on the wire. Nothing else about the
    // request survives the run, so the framing it needs is copied here.
    //
    // Lazy, like h2/ws/sse below: most connections never call
    // response.file=, and ten strings on every connection slot would be
    // paid for by the accept, recv and send path either way.
    //
    // Allocated on first use and kept for the life of the connection, so
    // a connection that serves file after file does not thrash malloc.
    // `reset()` and `~Conn()` are the only places that delete it.
    // Three sources meet here, and the names say which is which. The
    // kernel's fields are named for the arguments they become (openat,
    // io_uring_prep_read, munmap). HTTP's are named for their fields.
    // The access line's are copies: the request is gone by the time the
    // ring answers, so they are taken while it still exists.
    struct FileXfer {
      std::string pathname;      // openat(dirfd, pathname, flags)
      std::string head;          // RFC 9112 2.1: status-line + fields
      std::string content_type;  // RFC 9110 8.3
      std::string field_lines;   // RFC 9112 5: what the run added
      std::string buf;           // io_uring_prep_read(sqe, fd, buf, ...)
      std::string method_token;   // RFC 9110 9.1
      std::string request_target;  // RFC 9112 3.2
      std::string referer;         // RFC 9110 10.1.3
      std::string user_agent;      // RFC 9110 10.1.5
      size_t buf_filled = 0;  // how much of buf the read put there
      // RFC 9110 8.6: content_length is what Content-Length promised,
      // content_sent what has already gone out. The two being unequal is
      // the only thing that keeps a file alive across rounds.
      size_t content_length = 0;
      size_t content_sent = 0;
      // A mapped file: lent whole, in chunks no bigger than one send can
      // move. Like buf it deliberately survives file_clear() - the SQE
      // still points into it - and it goes back on the kDone round, which
      // is by construction the round after the last lend.
      const char* map_addr = nullptr;  // munmap(addr, length)
      size_t map_length = 0;
      bool map_wanted = false;         // no RFC: above file_map_threshold
      int64_t if_modified_since = 0;   // RFC 9110 13.1.3
      uint16_t status_code = 0;        // RFC 9110 15
      uint8_t log_flags = 0;           // LogRec::flags, see kLogH2
      FileStage stage = FileStage::kNone;
      bool persist = true;             // RFC 9112 9.3
      bool head_only = false;          // RFC 9110 9.3.2
      bool if_modified_since_valid = false;
      // Which form a refusal takes, weighed against the caller's Accept
      // while the request was still in hand.
      int err_media = 0;
      int minor = 1;                   // RFC 9112 2.3: HTTP-version's
                                       // second DIGIT
    };
    FileXfer* file = nullptr;
    // Nothing is owed and nothing is held: the state a fresh connection and
    // a delivered file both stand in. The allocation itself survives - see
    // FileXfer's comment above.
    void file_clear() {
      if (file == nullptr) return;
      file->stage = FileStage::kNone;
      file->buf_filled = 0;
      // The counters end with the transfer they counted. Leaving them for
      // the next request is how a stale content_length gets read as this
      // one's.
      file->content_length = 0;
      file->content_sent = 0;
      file->map_wanted = false;
      file->status_code = 0;
      file->log_flags = 0;
      file->pathname.clear();
      file->head.clear();
      file->content_type.clear();
      file->field_lines.clear();
      file->method_token.clear();
      file->request_target.clear();
      file->referer.clear();
      file->user_agent.clear();
    }
    // The address space goes back. Called from zc_release once the round
    // that borrowed the mapping has drained, and unconditionally when the
    // connection itself ends - a mapping nobody borrowed still has to go.
    void map_release() {
      if (file == nullptr || file->map_addr == nullptr) return;
      ::munmap(const_cast<char*>(file->map_addr), file->map_length);
      file->map_addr = nullptr;
      file->map_length = 0;
    }
    // The one end of the lend window - drained round, closed connection,
    // dead reactor. Never conditional on the round having succeeded.
    void zc_release() {
      // The mapping is not released from here. Which round may hand it back
      // is a decision, and decisions live in file_step(); this function
      // runs before that one and could only guess.
      // h2 lends per stream and hands each back where the stream ends,
      // but the last bytes are still in flight there. This is the point
      // that knows they are not, so the h2 backlog is freed here.
      if (h2 != nullptr) h2->content_drain();
      zc_covered = 0;
      zc_split = false;
      if (!zc_lent) return;
      zc_lent = false;
      resource_body_unlend(zc_mrb, zc_value);
      zc_mrb = nullptr;
    }
    // #30: take one in. The slot is the watcher's one name - the key it
    // is filed under here and the field its completions carry back - so
    // there is nothing to translate between the ring and the hash.
    // Returns the slot, or -1 when this connection is already holding
    // as many as a tag can name.
    int watchers_add(mrb_state* mrb, mrb_value w) {
      if (w_mrb == nullptr) {
        w_hash = mrb_hash_new(mrb);
        mrb_gc_register(mrb, w_hash);
        w_mrb = mrb;
      }
      for (int i = 0; i < static_cast<int>(kMaxWatchers); i++) {
        if (!mrb_nil_p(mrb_hash_get(mrb, w_hash, mrb_int_value(mrb, i)))) continue;
        watcher_set_slot(w, i);
        mrb_hash_set(mrb, w_hash, mrb_int_value(mrb, i), w);
        w_pending.push_back(i);
        return i;
      }
      return -1;
    }

    mrb_value watchers_at(int slot) const {
      if (w_mrb == nullptr) return mrb_nil_value();
      return mrb_hash_get(w_mrb, w_hash, mrb_int_value(w_mrb, slot));
    }

    // Gone for good: cancelled by the caller, then emptied here, so the
    // sweep that comes later finds nothing to free and nothing to cancel
    // a second time.
    void watchers_drop(int slot) {
      if (w_mrb == nullptr) return;
      const mrb_value w = watchers_at(slot);
      if (mrb_nil_p(w)) return;
      watcher_disarm(w);
      mrb_hash_delete_key(w_mrb, w_hash, mrb_int_value(w_mrb, slot));
    }

    // #30: let the watchers go. Unrooting the hash is the whole of it -
    // the watchers become collectable, and each one's CDATA destructor
    // is what finally takes its descriptor out of the ring.
    void watchers_release() {
      w_pending.clear();
      if (w_mrb == nullptr) return;
      mrb_gc_unregister(w_mrb, w_hash);
      w_mrb = nullptr;
      w_hash = mrb_nil_value();
    }
    // The connection itself is ending, and the ring may go before the
    // VM collects the watchers. Each one is emptied here, so its
    // destructor has no ring to cancel on, and then all are let go.
    void watchers_forget() {
      if (w_mrb != nullptr) {
        for (int i = 0; i < static_cast<int>(kMaxWatchers); i++) {
          const mrb_value w = watchers_at(i);
          if (!mrb_nil_p(w)) watcher_disarm(w);
        }
      }
      watchers_release();
    }
    // The Ring resets this; `li` is the App's key to "whose connection is
    // this", `pkt` says whether that listener is TCP.
    void reset(uint8_t li, bool pkt) {
      zc_release();
      watchers_release();
      // #80: a run still parked when the peer left. Its frame holds the
      // roots and the round; destroying the frame gives them back (see
      // ParkedRoots in run_parkable), and the park bits are free again.
      parked.destroy();
      h2_parked.clear();
      for (Round*& r : park) r = nullptr;
      park_taken = 0;
      park_owes = 0;
      map_release();
      delete file;
      file = nullptr;
      peer_len = 0;
      carry.clear();
      content_skip = 0;
      content_need = 0;
      body_hold.clear();
      run_wants_body = false;
      spill.close_file();
      listener = li;
      packetized = pkt;
      fresh = true;
      h2_free(h2);
      h2 = nullptr;
      ws_free(ws);
      ws = nullptr;
      sse_free(sse);
      sse = nullptr;
      asset = nullptr;
      asset_off = 0;
      asset_end = 0;
    }
    // A slot is built in place and moved once, when conns_ is sized.
    // Declared because the destructor below suppresses the implicit move,
    // and Run is move-only - without these the vector falls back to a
    // copy, which a coroutine handle must never have.
    // #80: Run is move-only (a coroutine handle must never be copied),
    // which deletes the implicit copy this struct used to have. Nothing
    // is declared in its place on purpose: a slot is built where it
    // lives and never moves, so the vector became a unique_ptr array -
    // see conns_. A defaulted move here would copy ws/sse/h2/file and
    // the GC registration and leave the source owning them too, and a
    // hand-written one is a member list that can be short by one.
    Conn() = default;
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;

    // The websocket, the stream, the h2 state and a response.file transfer
    // die with the connection.
    ~Conn() {
      zc_release();
      map_release();
      watchers_forget();
      delete file;
      h2_free(h2);
      ws_free(ws);
      sse_free(sse);
    }
  };

  struct AppInput {
    const RouteTable* table = nullptr;
    const Resource* const* resources = nullptr;
    size_t nroutes = 0;
    const RouteTable* ws_table = nullptr;
    const WsResource* const* ws_resources = nullptr;
    size_t ws_nroutes = 0;
    const RouteTable* sse_table = nullptr;
    const SseResource* const* sse_resources = nullptr;
    size_t sse_nroutes = 0;
    bool tls = false;
    // RFC 9110 15.5.14: conf.max_body, in octets. What this application
    // accepts as a request body before it answers 413.
    size_t max_body = kMaxBodyDefault;
  };

  Http1(const AppInput* apps, size_t napps, Assets* assets = nullptr);
  Http1(const RouteTable& table, const Resource* const* resources, size_t nroutes,
        Assets* assets = nullptr);

  // #210: the error pages render in a VM, and this layer is handed one
  // rather than owning it: the h1 model is bytes in, bytes out. A caller
  // that never calls this gets the bodyless statuses.
  void open_error_assets(mrb_state* mrb, Assets* error_assets);

  // A pack that was built again, put in the place of the one this layer
  // was handed. Every prebuilt block h2 keeps per entry belongs to the
  // entry, so this rebuilds them for the new pack and nothing else
  // changes. The old pack is not freed here - a response that is on the
  // wire is still lending its bytes, and the caller owns that decision.
  void swap_assets(Assets* assets);

  // The standalone tier: no app, and the docroot answers what the pack
  // does not. The media-type database is the server's, lent here for the
  // one thing this tier decides that the file machine does not - what a
  // name's Content-Type is.
  void serve_docroot(const MimeDb* mime) { mime_ = mime; }

  void on_tick();

  bool pending(const Conn& st) const;

  // WHATWG HTML: does this connection carry a source with its own schedule?
  // WHATWG HTML: which connections want a wake every second. h1 carries
  // one event stream on the connection; an h2 connection carries one per
  // stream, so it is asked as soon as any stream has one.
  bool timed(const Conn& st) const {
    if (st.sse != nullptr) return true;
    if (st.h2 == nullptr) return false;
    for (const H2Stream& s : st.h2->streams) {
      if (s.sse != nullptr) return true;
    }
    return false;
  }

  // No RFC - this becomes a struct msghdr, so it carries that struct's
  // names: the segments are its msg_iov, their count its msg_iovlen, and
  // each segment is an iovec. take_plan resolves them one to one.
  //
  // Two fields are not part of the ABI and say so. `off` is what makes a
  // segment resolvable at all: a sink segment cannot know its address
  // until the sink has stopped growing, so it carries an offset and gets
  // its iov_base at the last moment. And `byte_total` is the sum of the
  // iov_lens, which is what a round is measured against - it used to be
  // called iov_len too, one name for a segment's length and for every
  // segment's length together.
  struct Plan {
    struct Seg {
      const char* iov_base;
      size_t off;  // not ABI: where in the sink, when iov_base is null
      size_t iov_len;
    };
    // Not ABI: our own bound on how many segments one round may carry.
    static constexpr unsigned kSegs = 1023;
    Seg iov[kSegs];
    unsigned iovlen = 0;
    size_t byte_total = 0;
    size_t byte_cap = 0;
  };

  // Where an answer goes: the bytes the round appends to, and the plan
  // that will carry them (null where this caller is not planning a send).
  struct Sink {
    std::string& bytes;
    Plan* plan;
  };
  bool feed(Conn& st, std::string_view data, Sink out);

  // The sink has drained, and this connection may still owe bytes: a
  // stopped run, a file transfer, an event stream, an h2 frame, an
  // asset. This spells the next round of them, and when nothing is owed
  // it takes the next request out of the carry. It answers whether the
  // connection lives past that round.
  bool spell_next_round(Conn& st, std::string& sink, Plan& plan);

  // #80: the reactor saying a worker or a watcher answered. Only a flag -
  // the run is resumed in `spell_next_round`, where a sink and a plan exist.
  // The worker answered. The bytes come back into the reactor's VM
  // here, which is the only thread that may build a value in it. A
  // worker that raised, or an answer CBOR cannot carry, is nil - the
  // run reads it like any other answer and decides for itself.
  static void compute_task_answered(Conn& st, int park, int job, const ComputeAnswer& answered);
  // #30: one job of a round answered, whatever answered it.
  static void round_answered(Conn::Round& r, int job, mrb_value v);
  // The job a stopped run left, or nullptr. Taken, not read: the reactor
  // arms it once and the connection stops naming it - exactly file_take.
  // Every worker slot is taken. The run is told rather than the layer
  // inventing a refusal - it answers this the way it answers anything.
  static void compute_task_refused(Conn& st, int park) {
    Conn::Round* const r = st.park_at(park);
    if (r == nullptr) return;
    r->answer_ready = true;
    r->compute_task_full = true;
  }
  // The three refusals a stopped run can meet, told apart here so no
  // call site has to. Status 0 means the
  // worker answered and the run reads the answer.
  //
  // Retry-After holds a whole header line, ready to append: these are
  // the only three the refusals send, and they are constants so a
  // refusal costs no formatting and no allocation.
  struct ComputeRefusal {
    uint16_t status = 0;
    std::string_view retry_after;
  };
  static ComputeRefusal compute_task_refusal(Conn::Round& round) {
    // A full pool is load, and load passes. The seconds move over 3..5
    // so a burst that was refused together does not come back together.
    if (round.compute_task_full) {
      static const char* const kWait[3] = {"Retry-After: 3\r\n", "Retry-After: 4\r\n",
                                           "Retry-After: 5\r\n"};
      static unsigned turn = 0;
      return {429, kWait[turn++ % 3]};
    }
    // The author's number was wrong. Coming back does not make the work
    // shorter, so nothing tells the client to.
    if (round.compute_task_over_deadline) return {500, {}};
    // A handle the worker needs is gone. A database that is restarted
    // comes back, and a minute is the size of that, not the seconds a
    // burst of load lives on.
    if (round.compute_task_raised) return {503, "Retry-After: 60\r\n"};
    return {};
  }
  // #80: the crossing, done by the frame at the stop. The block becomes
  // an id and the arguments become CBOR. After this nothing of the VM is
  // named, which is what lets a worker touch the result at all.
  static bool compute_task_hand_over(Conn& st, Conn::Round& round, int park, const Resource& res);
  // #30: the watcher a stopped run left, handed to the connection. The
  // connection files it under a slot and roots it; the reactor arms what
  // `w_pending` names. False when the connection can hold no more, and
  // the run is told the way a full pool tells it.
  static bool watch_hand_over(Conn& st, Conn::Round& round, int park, const Resource& res);
  // What one event did to the wait.
  enum class WatchStep : uint8_t {
    kWait,    // the block wants the same thing again
    kRearm,   // the block asked for other events
    kDone,    // the block called abort; `answer_value` is its last word
  };
  // #30: one readiness, delivered to the block. The block decides what
  // happens next, and it says so through the watcher: `abort` ends the
  // wait, `events=` changes what to wait for, anything else waits again.
  // The return value never means "keep waiting" - a block may answer nil
  // and mean it.
  static WatchStep watcher_event(Conn& st, int slot, unsigned revents);
  // The watcher was quiet for as long as it allowed. The block hears
  // `:timeout` and answers whether the wait goes on.
  static WatchStep watcher_deadline(Conn& st, int slot);
  // What a watcher waits for right now, as poll bits, and how long it
  // may stay quiet. The reactor asks both when it arms one.
  static unsigned watcher_mask(Conn& st, int slot);
  static int watcher_descriptor(Conn& st, int slot);
  static void watcher_is_armed(Conn& st, int slot, struct io_uring* ring, uint64_t tag);
  static void watcher_is_unarmed(Conn& st, int slot);
  // The tag of the poll in the ring for this watcher, or 0 when none is.
  static uint64_t watcher_poll_tag(Conn& st, int slot);
  static void watchers_drop_slot(Conn& st, int slot);
  // A watcher this connection has not armed yet. Taken, not read: the
  // reactor arms it once and the connection stops naming it - exactly
  // file_take and compute_task_take.
  static bool watch_take(Conn& st, int* slot) {
    if (st.w_pending.empty()) return false;
    *slot = st.w_pending.back();
    st.w_pending.pop_back();
    return true;
  }
  // Which watcher this connection waits on, or -1.
  // #30: the watcher slot each job of the round waits on, or -1. A
  // round can wait on several at once.
  // The other way round: which job a watcher slot answers, or -1 when
  // this connection is not waiting on it.
  // #30: where the run that owns these watchers is waiting. Told after
  // the park, because only then does the frame hold its own state.
  static void watch_run_is(Conn& st, Conn::Round& round, Resource::RunState* run);
  // #30: every watcher of this connection that stayed quiet for as long
  // as the watcher itself allowed. The sweep asks once per connection, not once per
  // watcher, and this walks the ones that are armed.
  static size_t watchers_over_deadline(Conn& st, int64_t now, int* slots, size_t max);
  // The earliest deadline any armed watcher of this connection owes, or
  // 0 when none does. The Ring keeps that one number.
  static int64_t watchers_soonest_deadline(Conn& st);
  static void watcher_armed_at(Conn& st, int slot, int64_t at);
  static double watcher_quiet_seconds(Conn& st, int slot);
  // The work a stopped run left, or false. Taken, not read: the reactor
  // arms it once and the connection stops naming it - exactly file_take.
  // #30: response.userdata for this job, as the crossing left it.
  static std::string_view compute_task_user(const Conn& st, int park, int job) {
    const Conn::Round* const r = st.park_at(park);
    if (r == nullptr || job < 0 || job >= Conn::kJobSlots) return {};
    return r->job[job].user_bytes;
  }
  static bool compute_task_take(Conn& st, int park, int job, unsigned* code, std::string& bytes,
                                double* deadline) {
    Conn::Round* const r = st.park_at(park);
    if (r == nullptr || job < 0 || job >= Conn::kJobSlots) return false;
    Conn::Round::Job& j = r->job[job];
    if (!j.waiting) return false;
    *code = j.code;
    *deadline = j.deadline;
    bytes.swap(j.bytes);
    j.bytes.clear();
    j.waiting = false;
    return true;
  }
  // response.file, the reactor's half. A bound run may name a file instead
  // of spelling a body; opening it is disk work, so it never happens inside
  // the run. These five are the whole contract with the Ring - it drives
  // openat2/statx/read through the ring and hands each result back here,
  // and the answer reaches the wire through `spell_next_round` like every other
  // continuation. Any refusal - a miss, a directory, a resolve flag
  // catching an escape - lands as the same 404 file_reject spells.
  const char* file_take(Conn& st);
  // The question file_take answers, asked without a call. The reactor
  // asks it on every recv and every round, and the answer is almost
  // always no: file_take lives in another translation unit, so the no
  // cost a call and a return. Measured at 0.38% of a whole h1 run.
  static bool file_waiting(const Conn& st) {
    return st.file != nullptr && st.file->stage == FileStage::kNamed;
  }
  // The same, for the work a stopped run left. arm_compute_task built a
  // std::string before it asked. Measured at 0.45%.
  static bool compute_task_waiting(const Conn& st) { return st.park_owes != 0; }
  static uint8_t park_generation(const Conn& st, int park) {
    return park >= 0 && park < Conn::kParkSlots ? st.park_gen[park] : 0;
  }
  // The next parked run with a job to arm, or false. Taken, not read -
  // the same shape as file_take and watch_take.
  static bool park_take_pending(Conn& st, int* park) {
    if (st.park_owes == 0) return false;
    const int slot = __builtin_ctz(st.park_owes);
    st.park_owes &= static_cast<uint16_t>(~(1u << slot));
    *park = slot;
    return true;
  }
  void file_reject(Conn& st);
  void file_error(Conn& st, const char* why);
  bool file_stat(Conn& st, const struct statx& stx, size_t* want);
  char* file_buffer(Conn& st, size_t n);
  void file_ready_now(Conn& st, size_t n);
  void file_mapped(Conn& st, const char* p, size_t n);
  // Is a round waiting for `spell_next_round` to run? kDone counts: it puts nothing on
  // the wire, but it is the round that hands the mapping back and writes
  // the access line, so nothing may go idle in front of it.
  static bool file_answerable(const Conn& st) {
    return st.file != nullptr &&
           (st.file->stage == FileStage::kDeliver || st.file->stage == FileStage::kDone);
  }
  // #36: a run of this connection stopped for the request body, and the
  // body is whole. Its answer owes the ring no completion - the octets
  // came in on the receive that just fed the parser - so nothing else
  // would ever come back to collect it. The reactor asks this instead,
  // the way it asks file_answerable.
  static bool run_resumable(const Conn& st) {
    if (mrb_likely(!st.run_parked())) return false;
    const Conn::Round* const r = st.park_at(st.parked.co.promise().park);
    return r != nullptr && r->answer_ready;
  }
  // 0 = do not map; otherwise the exact length to map. One question, one
  // answer - the split that made the read path ask "map?" and then use the
  // map's length to read with.
  static size_t file_map_len(const Conn& st) {
    return (st.file != nullptr && st.file->map_wanted) ? st.file->content_length : 0;
  }
  // Which shape a resource's answer takes. One value, decided once, so
  // the writer and the access line below cannot disagree about what went
  // out.
  struct AnswerStep {
    enum class Shape : uint8_t {
      kAlready,    // the dynamic-head branch already spelled it
      kLent,       // a lent body behind the 200 prefix
      kGzip,       // conneg between identity and gzip
      kPlain,      // a copied body behind the 200 prefix
      kException,  // a 500 the resource spelled itself (may demote)
      kStatus      // a prebuilt status line and nothing else
    };
    Shape shape = Shape::kStatus;
    size_t body_len = 0;  // what the access line counts
    bool answered = false;
  };
  // What one run left behind, which is all the shape depends on: the status
  // it reached, the body it spelled or lent, whether the head branch above
  // already answered, and what the route allows.
  struct AnswerFacts {
    uint16_t status;
    size_t body_len;
    size_t lent_len;
    bool answered_already;
    bool have_body;
    bool has_lent;
    bool gzip_ok;
    bool bound;
  };
  static AnswerStep answer_step(const AnswerFacts& f) {
    AnswerStep s;
    s.body_len = f.has_lent ? f.lent_len : f.body_len;
    s.answered = f.answered_already;
    if (f.have_body && f.status == 200) {
      s.shape = f.has_lent ? AnswerStep::Shape::kLent
                           : (f.gzip_ok ? AnswerStep::Shape::kGzip : AnswerStep::Shape::kPlain);
      s.answered = true;
    } else if (f.answered_already) {
      s.shape = AnswerStep::Shape::kAlready;
    } else if (f.status == 500 && f.bound) {
      // Whether a body exists is a question for the VM, so the caller
      // demotes this to kStatus when the answer is no.
      s.shape = AnswerStep::Shape::kException;
    } else {
      s.shape = AnswerStep::Shape::kStatus;
    }
    return s;
  }

  // RFC 9113 6.9.1: what one stream may put on the wire this round. Both
  // windows, what is left of the body, and - for a copied buffer only -
  // the delivery chunk. This was the same twenty lines three times over,
  // once per source, each computing the budget again and each writing in
  // the middle of the arithmetic.
  // How many bytes of the stream's body go out this round. It no longer
  // picks among sources - there is one - so it decides a count and nothing
  // else; where the bytes come from is H2Stream::Body's business.
  struct H2SendStep {
    size_t start = 0;   // first byte of the body this round frames
    size_t give = 0;    // how many bytes it may frame
    size_t total = 0;   // the body's length, so END_STREAM is a comparison
    bool ends = false;  // give reaches the last byte
  };
  // What the connection allows this round: what is left of its own flow
  // window, and the largest copy this round is willing to make.
  struct RoundRoom {
    int64_t conn_window;
    size_t chunk;
  };
  static H2SendStep h2_send_step(const H2Stream& s, RoundRoom room) {
    const int64_t conn_window = room.conn_window;
    const size_t chunk = room.chunk;
    H2SendStep o;
    if (!s.response_content.owes()) return o;
    o.start = s.response_content.sent;
    o.total = s.response_content.length;
    size_t remaining = s.response_content.length - s.response_content.sent;
    // A copied buffer is bounded per round; a lend and a mapping are not.
    if (s.response_content.src == H2Stream::Content::Src::kOwned && remaining > chunk) {
      remaining = chunk;
    }
    const int64_t budget = conn_window < s.flow_window ? conn_window : s.flow_window;
    if (budget <= 0) return o;  // owed, but the window is shut: give stays 0
    o.give = remaining;
    if (static_cast<int64_t>(o.give) > budget) o.give = static_cast<size_t>(budget);
    o.ends = o.give != 0 && o.start + o.give == o.total;
    return o;
  }

  // What the asset tier does with one request: computed here, performed
  // by the caller. One value, so nothing is decided inside a branch that
  // is already writing.
  //   status_code      RFC 9110 15 - and what the access line says
  //   first_byte_pos   RFC 9110 14.1.2
  //   content_length   RFC 9110 8.6 - the span sent, and what the access
  //                    line counts
  //   sends_content    RFC 9110 6.4
  struct AssetStep {
    // Which of the four heads this request gets; the enum is HeadKind, not
    // Head, because AssetEntry::Head is a head - this only picks one.
    enum class HeadKind : uint8_t { kRefusal, kNormal, kRange, kUnsatisfiable };
    HeadKind head = HeadKind::kNormal;
    uint16_t status_code = 200;
    size_t first_byte_pos = 0;
    size_t content_length = 0;
    bool sends_content = false;
  };
  // RFC 9110 14.1/14.2: a range is honoured only on a GET that would have
  // been a 200, and only when If-Range still matches the representation.
  // What the range decision weighs besides the entry: the verdict c4 has
  // already reached, and what the request asked for.
  struct RangeAsk {
    uint16_t verdict;
    bool head_only;
    flow::Method method;
    const http::ReqValues& vals;
  };
  static AssetStep asset_step(const AssetEntry& e, const RangeAsk& ask) {
    const uint16_t verdict = ask.verdict;
    const bool head_only = ask.head_only;
    const http::ReqValues& vals = ask.vals;
    AssetStep s;
    s.status_code = verdict;
    if (verdict == 412 || verdict == 501) {
      s.head = AssetStep::HeadKind::kRefusal;
      return s;
    }
    const size_t complete_length = Assets::wire_len(e);
    if (verdict == 200 && !head_only && ask.method == flow::Method::kGet &&
        vals.range != nullptr &&
        (vals.if_range == nullptr ||
         http::if_range_matches({vals.if_range, vals.if_range_len}, {e.etag, sizeof(e.etag)}))) {
      http::ByteRange r = {0, 0};
      switch (http::parse_range({{vals.range, vals.range_len}, complete_length}, r)) {
        case http::RangeParse::kOne:
          s.head = AssetStep::HeadKind::kRange;
          s.status_code = 206;
          s.first_byte_pos = r.first;
          s.content_length = r.last - r.first + 1;
          s.sends_content = true;
          break;
        case http::RangeParse::kUnsat:
          s.head = AssetStep::HeadKind::kUnsatisfiable;
          s.status_code = 416;
          return s;
        case http::RangeParse::kNone:
          break;
      }
    }
    if (s.head == AssetStep::HeadKind::kNormal && verdict == 200 && !head_only) {
      s.content_length = complete_length;
      s.sends_content = true;
    }
    return s;
  }

  // The next round of a transfer, computed and not performed.
  //
  // Defined here, not in a .cpp: `spell_next_round` lives in another translation unit
  // and this build has no LTO, so a definition over there would be a real
  // call with a 48-byte return through memory (SysV returns anything past
  // 16 bytes that way). Inlined, the FileStep never exists - the compiler
  // keeps its fields in registers. Purity only pays where the compiler can
  // see it.
  static FileStep file_step(const Conn::FileXfer& x, size_t chunk) {
    FileStep s;
    s.persist = x.persist;
    s.sent_after = x.content_sent;
    s.next = x.stage;
    switch (x.stage) {
      case FileStage::kDeliver: {
        const bool mapped = x.map_addr != nullptr;
        const size_t left =
            x.content_length > x.content_sent ? x.content_length - x.content_sent : 0;
        // A mapping lends a bounded chunk of itself; a window lends exactly
        // what the read put in it.
        const size_t take = mapped ? (left < chunk ? left : chunk) : x.buf_filled;
        s.head = !x.head.empty();
        if (take != 0) {
          s.src = mapped ? FileStep::Src::kMapping : FileStep::Src::kWindow;
          // A mapping is walked from where the transfer stands; the window
          // buffer holds only this round's bytes and starts at zero.
          s.start = mapped ? x.content_sent : 0;
        }
        s.give = take;
        s.sent_after = x.content_sent + take;
        // A window is refilled by the ring, so the next round waits on it.
        // A mapping has no read coming to wake it and drives itself.
        s.next = s.sent_after < x.content_length
                     ? (mapped ? FileStage::kDeliver : FileStage::kRing)
                     : FileStage::kDone;
        break;
      }
      case FileStage::kDone:
        // The last lend has drained - that is what kDone means and the only
        // way to reach it. So this is where the mapping goes back and where
        // the transfer's one access line is owed.
        s.release_map = x.map_addr != nullptr;
        s.log = true;
        s.clear = true;
        s.next = FileStage::kNone;
        break;
      default:
        break;
    }
    return s;
  }
  // The one place a transfer's state changes as a round is delivered.
  void file_apply(Conn& st, const FileStep& step);
  // The single access line of a transfer, with the bytes that really went
  // out. Called on the kDone round, or by file_abandon when a connection
  // dies under one; the stage is what keeps it from happening twice.
  void file_log(Conn& st);
  // A connection closing under a transfer still owes its access line.
  void file_abandon(Conn& st);
  // Nothing owed, nothing on the wire: give the read buffer back, or a slot
  // that once served a big file would hold those bytes for the process's
  // life. The Ring calls this only where both are true.
  static void file_release(Conn& st) {
    if (st.file != nullptr && st.file->buf.capacity() > kDeliverChunk) {
      std::string().swap(st.file->buf);
    }
  }

  // The App formats lines; the Ring flushes the buffer. Opt-in.
  Logger* access_log() { return &alog_; }
  // The only way an access line is ever built.
  void enable_access_log() { alog_.enabled = true; }
  // The second stream: its own socket, its own daemon, its own file.
  Logger* error_log() { return &elog_; }
  // The only way an error record is ever built.
  void enable_error_log() { elog_.enabled = true; }
  // [tune] zero_copy_threshold, once, before the first accept.
  void set_zero_copy_threshold(size_t n) { zc_min_ = n; }

  // [tune] file_map_threshold, once, before the first accept. 0 = never map.
  void set_file_map_threshold(size_t n) { map_min_ = n; }
  // The Ring owns the send clock, so the Ring is what tells this layer how
  // much one send may carry - one rule, one place.
  void set_send_timeout(int secs) { send_chunk_ = file_send_chunk(secs); }

  // The Ring asks before it opens: the size that decides this is the App's
  // to weigh, because the App is what holds the operator's answer.

 private:
  struct AppSlot;

  // RFC 6455 4.1: what a websocket upgrade needs to know about the request
  // that asked for it. One argument instead of eleven - see #std-first: the
  // arguments that always travel together are a thing without a name, and
  // this is that thing. Every member is a view or a reference into bytes
  // the caller owns for the length of the call.
  // WHATWG HTML: what an event-stream route needs to know about the request
  // that asked. Same reason as WsUpgrade below - see #std-first.
  struct SseBegin {
    const AppSlot& slot;
    int route;
    std::string_view method;
    std::string_view path;
    const RouteSpans& spans;
    const void* hdrs;   // struct phr_header[]; the framer's header is not here
    size_t nhdr;
    int minor;
    flow::Method m;
    const http::ReqValues& vals;
    uint8_t lflags;
  };

  struct WsUpgrade {
    const AppSlot& slot;
    int route;
    std::string_view path;
    const RouteSpans& spans;
    std::string_view key;
    const void* hdrs;   // struct phr_header[]; the framer's header is not here
    size_t nhdr;
    const http::ReqValues& vals;
    std::string_view rest;  // bytes after the head, already in hand
  };

  struct Resp {
    std::string bytes;
    size_t date_off = 0;
  };
  struct Variants {
    Resp plain, keep, close;
  };
  struct H2Block {
    std::string bytes;
  };

  // #210: where an error answer's own HPACK block and its rendered page
  // are built. Both outlive the framing, because a body the window cannot
  // finish is copied onto the stream from here.
  struct H2ErrorPage {
    H2Block block;
    std::string rendered;
  };

  // What one h2 answer puts on the wire: the HPACK block that heads it and
  // the body bytes that follow.
  struct H2Answer {
    const char* body = nullptr;
    size_t blen = 0;
    const H2Block* blk = nullptr;
  };

  struct Bundle;

  // And what spelling an error answer needs to know first: the status it
  // carries, the words #210 filled in for it, the header values the request
  // frame still holds (for Accept), and the route whose Allow a 405 keeps.
  struct H2ErrorAsk {
    uint16_t status;
    const ErrorPages::Fields& fields;
    const http::ReqValues* vals;
    const Bundle* bundle;
  };

  struct Bundle {
    flow::KonstSet konst;
    // RFC 9110 12.5.1: what c4 weighs an Accept against - the media type
    // without the charset parameter konst.content_type grows here, and
    // present even for the default route, which has no Resource behind it.
    std::string accept_type;
    const Resource* res = nullptr;
    std::array<uint16_t, 600> index {};
    bool dynamic_body = false;
    bool bound = false;
    bool gzip_ok = false;
    Variants ok_head;
    Variants ok_prefix;
    Variants ok_prefix_vary;
    Variants ok_prefix_gzip;
    Variants err_prefix;
    H2Block h2_err;
    std::string h2_data200;
  };

  void build(const AppInput* apps, size_t napps);
  // RFC 9112 9.3: one status prebuilt - the code, the fields that always go
  // with it, the body it carries where it carries one, the Date bytes laid
  // down (a placeholder at boot; the second's own from then on), and the
  // Connection field of the spelling being built.
  struct Prebuilt {
    uint16_t status;
    const char* extra;
    const char* body;
    const char* date;
    const char* conn = "";
  };
  static void build_variants(Variants& v, Prebuilt p);
  static void build_one_variant(Resp& r, Prebuilt p);
  static void copy_without_tail(const Resp& src, Resp& dst, size_t cut);
  // RFC 9112: a head that stops before Content-Length, for a body the run
  // has yet to produce - the status line, the route's own fields, whatever
  // Vary / Content-Encoding applies, and the Connection field of the
  // spelling being built.
  struct OpenPrefix {
    const char* status_line;
    const std::string& extra;
    const char* enc;
    const char* conn = "";
  };
  static void build_open_prefixes(Variants& v, OpenPrefix p);
  static void build_open_prefix(Resp& r, OpenPrefix p);
  // RFC 9113 6.2: one whole HEADERS frame for the cache to replay - the
  // route's prebuilt block, the per-answer fields, and the date.
  struct CachedHead {
    const H2Block& block;
    std::span<const unsigned char> fields;
    std::span<const unsigned char> date;
  };
  static void cache_headers(std::string& out, const CachedHead& head);
  // WHATWG HTML: an event stream's one access record. SseLine is what the
  // seven arguments were - see #std-first.
  struct SseLine {
    std::string_view method;
    std::string_view path;
    const http::ReqValues& vals;
    uint16_t status;
    uint8_t lflags;
  };
  static void log_sse(Logger& lg, const Conn& st, const SseLine& line);
  // What one prebuilt status says beyond its status line: the fields that
  // always go with it, and the body it carries where it carries one.
  struct StatusText {
    const char* extra;
    const char* body;
  };
  void build_status(uint16_t status, StatusText t);
  void stock_status(bool have[600], uint16_t s);
  void build_bundle(Bundle& b, const Resource* res);
  static void patch_date(Variants& v, const char* core);
  // RFC 9112: one prebuilt head and the body behind it - a HEAD request
  // takes the same head and none of the bytes.
  struct Assembled {
    const Resp& prefix;
    std::string_view body;
    bool head_only;
  };
  static void assemble(std::string& sink, const Assembled& a);
  bool feed_parse(Conn& st, std::string_view data, Sink out);
  // The cold branches of feed_parse, out of line: the protocol decision
  // on a fresh connection, and a head that upgrades or opens a stream.
  enum class Preface : uint8_t { kH1, kH2, kWait, kRefused };
  Preface h1_preface(Conn& st, const char* data, size_t len, std::string& sink,
                     size_t* consumed);
  struct H1Head {
    std::string_view method;
    std::string_view path;
    int minor;
    const struct phr_header* headers;
    size_t num_headers;
    const flow::ReqFacts& facts;
    const http::ReqValues& vals;
    uint8_t lflags;
    bool wants_ws;
    int ws_version;
    const char* ws_key;
    size_t ws_key_len;
    const char* rest;
    size_t rest_len;
  };
  bool h1_upgrade_or_stream(Conn& st, const H1Head& h, std::string& sink, bool* lives);
  static void claim_sink(Conn& st, const std::string& sink, Plan& plan);
  // The bytes one answer lends rather than copies, and the plan they are
  // lent into.
  struct Lending {
    std::string_view body;
    Plan& plan;
  };
  static void lend_body(Conn& st, std::string& sink, Lending lend);
  // RFC 9110 12.5.3/12.5.5: what a dynamic 200 chooses between - the two
  // prebuilt prefixes, whether gzip is on the table at all (the peer
  // accepts it and this connection is packetized), and whether the request
  // wants the body behind the head.
  struct DynamicBody {
    const Resp& prefix_id;
    const Resp& prefix_gz;
    // The bytes the run spelled. Handed in, never read off a member: a
    // parked run writes into its own string, and the writer's own is
    // already carrying the next request by the time this runs.
    const std::string& body;
    bool may_gzip;
    bool head_only;
  };
  void assemble_dynamic(const DynamicBody& d, std::string& sink);
  // RFC 9112 9.3: one prebuilt status in its three connection spellings.
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];
  }
  // The same status without its Content-Length and terminator: what an
  // error answer that has a page puts its own two fields behind.
  const Variants& prefixes(uint16_t status) const {
    return store_prefix_[index_[status]];
  }
  // RFC 9110 15: the error answer this connection gets. The prebuilt
  // status line and Date, then the page rendered for this request.
  //
  // With no page - no VM handed over, or a template that raised - the
  // bodyless status goes out instead.
  // The parts of one: the prefix its status line and Date come from, the
  // bodyless spelling that stands when there is no page, the status, the
  // media the page renders in, the words #210 filled in, and whether the
  // request wants the body behind the head.
  struct ErrorAnswer {
    const Resp& prefix;
    const Resp& bodyless;
    uint16_t status;
    int media;
    const ErrorPages::Fields& fields;
    bool head_only;
  };
  void spell_error(const ErrorAnswer& e, std::string& sink);
  // #80: everything a stopped run borrowed, rebased onto bytes it owns.
  // Named Held and not Parked because Http1 already has a Parked, and
  // that one is an h2 stream's view - a different thing entirely.
  //
  // What borrows, and it is more than ReqValues: ReqView's
  // request_target and method_token, the framer's phr_header array with
  // a name and a value each, and RouteSpans' captures. All of it points
  // into one contiguous head - the provided buffer, or carry - so one
  // delta moves the lot, and the only way to get that wrong is to miss a
  // member. Hence kReqValueSpans and its size assert.
  //
  // The body is not held here. Today it is the bytes right behind the
  // head and could ride along; tomorrow it is an O_TMPFILE that a read
  // has to fetch, and then it is not a span at all. Holding it apart
  // from the start is what keeps that from being a second rewrite.
  struct Held {
    // The bytes. Everything below points into this string, so it must
    // not move once hold() has run - no append, no reserve, no swap.
    std::string head;
    // The body, when the request carried one in the same buffer. Copied
    // for the same reason as the head: the buffer goes back to the kernel.
    std::string content;
    http::ReqValues vals{};
    RouteSpans spans{};
    ReqView rv{};
    std::unique_ptr<struct phr_header[]> fields;
    size_t nfields = 0;

    Held();
    ~Held();
    Held(Held&&) noexcept;
    Held& operator=(Held&&) noexcept;
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;

    // Copy the head and re-point `from` at the copy. After this the
    // provided buffer may go back to the kernel, which is the whole
    // point - see Run.
    void hold(const char* head_at, size_t head_len, const ReqView& from);
  };

  // What one request round already knows by the time the head is parsed.
  // A step that leaves the straight line takes this instead of twenty
  // arguments - which is what made those steps stay inline before.
  struct Round {
    Conn& st;
    const Bundle* b;
    const char* view;
    size_t viewlen;
    size_t off;
    size_t head_len;
    bool in_place;
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor;
    bool persist;
    bool head_only;
    size_t content_length;
    uint8_t lflags;
    const flow::ReqFacts& facts;
    const http::ReqValues& vals;
  };

  // What a step that may take the round over answers with.
  enum class Took : uint8_t {
    kNo,           // not this step's request; the straight line continues
    kNextRequest,  // answered, and the pipeline may hold another
    kOwed,         // answered so far as it can be; bytes are still owed
    kClose         // answered, and the connection ends
  };

  // #80: what the bound answer needs beyond the Round. It cannot sit
  // inline in feed_parse: a run that parks returns out of it and comes
  // back later, which a block in a loop body cannot do. A dozen values
  // that travel together are a type, like Spelling below.
  struct BoundAsk {
    const void* fields;
    size_t nfields;
    const RouteSpans& spans;
    const RouteTable* table;
    int route;
    Plan* plan;
    std::string& sink;
    // Where the run writes its body and its field lines. They used to be
    // two Http1 members, reused request after request. A run that parks
    // may not share them: the next request on this connection's ring
    // would write over what the parked one still owes, so a parked run
    // brings its own and the straight path keeps handing in the pair it
    // always reused.
    std::string& body;
    std::string& rhdrs;
  };
  // What the bound branch produced. `answered` means it spelled its own
  // head into the sink and the answer switch has nothing left to do.
  struct BoundOut {
    uint16_t status = 0;
    bool have_body = false;
    bool answered = false;
    // Read once here and used twice: the zero-copy gate inside, and
    // assemble_dynamic in the answer switch outside. Accept-Encoding does
    // not change between the two, so it is not read twice.
    bool accept_gzip = false;
    const char* lent = nullptr;
    size_t lent_len = 0;
  };
  // What the walk is handed, built once and read by both entries. The
  // ReqView is a member and not a return value because everything in it
  // points at bytes somebody else owns, and the owner has to outlive it.
  struct BoundPrep {
    ReqView rv;
    size_t zc_min = 0;
    bool accept_gzip = false;
  };
  void bound_prepare(Round& r, const BoundAsk& ask, BoundPrep& prep);

  // #80: everything a stopped run has to keep about the request, by
  // value. The Round it is built from holds references into feed_parse's
  // frame, and that frame is gone the moment the run stops - so the
  // coroutine takes copies and re-seats them at `head` once hold() has
  // run.
  struct BoundStart {
    const Bundle* b;
    const char* head_at;  // the request head's first byte, for hold()
    const char* view;
    size_t viewlen;
    size_t off;
    size_t head_len;
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    size_t content_length;
    const void* fields;
    size_t nfields;
    RouteSpans spans;
    const RouteTable* table;
    flow::ReqFacts facts;
    http::ReqValues vals;
    int route;
    int minor;
    uint8_t lflags;
    bool in_place;
    bool persist;
    bool head_only;
  };
  // The whole bound answer for a resource that declared a compute task, in a
  // frame that can stop. A resource that declared none never reaches
  // this and pays no frame.
  // #30: what a parkable run starts from. One coroutine serves both
  // protocols, because there must be one place where a run stops: the
  // frame that suspends holds everything about that run, and a second
  // copy of this machinery would be a second answer to the same
  // question. The tails differ - h1 spells a head and a body, h2 frames
  // HEADERS and DATA - and the stop between them does not.
  struct RunStart {
    enum class Proto : uint8_t { kH1, kH2 };
    Proto proto = Proto::kH1;
    // proto == kH1. The bytes of the request, and everything the parse
    // read out of them.
    BoundStart h1{};
    // proto == kH2. Copies, because the dispatch buffers die with the
    // round that read them and a parked run answers after that. It is
    // the same reason h1 holds its head.
    struct H2Start {
      uint32_t stream_id = 0;
      uint16_t route = 0;
      bool head_only = false;
      flow::ReqFacts facts{};
      std::string target;
    };
    H2Start h2{};
  };
  Run run_parkable(Conn& st, RunStart s, std::string* sink, Plan* plan);
  // What one such round leaves for the parse to do next.
  enum class ComputeRound : uint8_t {
    kNext,    // answered here; read the next request out of this buffer
    kParked,  // stopped; what is left waits in the carry
    kClosed,  // the answer was the connection's last
  };
  // The whole compute round, OUT of feed_parse. It is cold: a resource
  // that never said `compute` does not reach it, and feed_parse is the
  // hottest function in the server. Inlined
  // here it was paid for by every request that never
  // ran a compute task.
  __attribute__((noinline)) ComputeRound start_compute_round(Conn& st, const BoundStart& s,
                                                             std::string* sink, Plan* plan,
                                                             size_t& off);

  // kOwed = nothing is answered yet: the body is still coming, or a file
  // is being fetched through the ring.
  Took answer_bound(Round& r, const BoundAsk& ask, BoundOut& out);
  // The half after the walk. Reached from answer_bound and, once a run
  // can park, from the coroutine a promising resource runs through.
  Took bound_finish(Round& r, const BoundAsk& ask, BoundOut& out);

  // #80: what the answer switch needs beyond the Round - the sink it
  // writes to, the plan a lend rides out on, and what the run left
  // behind. A struct because these travelled together as nine
  // arguments, and #std-first says that is a type.
  struct Spelling {
    std::string& sink;
    Plan* plan;
    uint16_t status;
    const char* lent;
    size_t lent_len;
    bool answered;
    bool have_body;
    bool accept_gzip;
    const std::array<uint16_t, 600>* idx;
    // Same reason as DynamicBody::body: the run that spelled these bytes
    // may be one that stopped, and then they are not the writer's.
    const std::string& body;
  };
  // #80: the answer, spelled. Split out of feed_parse so the bound tier can
  // reach it from inside a coroutine while the konst tier keeps calling it
  // straight - a run that can never stop must not pay for a frame.
  // Returns the step it took, because the access line counts what it wrote.
  AnswerStep spell_answer(Round& r, Spelling sp) {
    Conn& st = r.st;
    const Bundle* const b = r.b;
    const int minor = r.minor;
    const bool persist = r.persist;
    const bool head_only = r.head_only;
    const http::ReqValues& vals = r.vals;
    const char* const method = r.method;
    const size_t method_len = r.method_len;
    const char* const path = r.path;
    const size_t path_len = r.path_len;
    std::string& sink = sp.sink;
    Plan* const plan = sp.plan;
    const uint16_t status = sp.status;
    const char* const lent = sp.lent;
    const size_t lent_len = sp.lent_len;
    const bool answered = sp.answered;
    const bool have_body = sp.have_body;
    const bool accept_gzip = sp.accept_gzip;
    const std::array<uint16_t, 600>* const idx = sp.idx;
    AnswerStep astep = answer_step({status, sp.body.size(), lent_len, answered, have_body,
                                    lent != nullptr, b != nullptr && b->gzip_ok,
                                    b != nullptr && b->bound});
    mrb_value exc_value = mrb_nil_value();
    // #210: what led here, gathered once - the record and the page carry
    // the same hash because they are taken over the same facts.
    ErrFacts ef;
    std::string ef_backtrace;
    std::string ef_steering;
    char ef_hash[kFingerprintLen] = {};
    if (mrb_unlikely(astep.shape == AnswerStep::Shape::kException)) {
      ef.peer = st.peer;
      ef.peer_len = st.peer_len;
      ef.request_target = path;
      ef.request_target_len = path_len;
      ef.method = method;
      ef.method_len = method_len;
      spell_steering(&vals, ef_steering);
      ef.steering = ef_steering.data();
      ef.steering_len = ef_steering.size();
      // The request as the resource saw it: lent for this frame, which is
      // the frame still being answered.
      ef.body = b->res->run.req != nullptr ? b->res->run.req->content : nullptr;
      ef.body_len = b->res->run.req != nullptr ? b->res->run.req->content_len : 0;
      ef.body_full = ef.body_len;
      ef.status_code = 500;
      exception_facts(b->res->mrb, {ef, ef_backtrace});
      spell_fingerprint(ef_hash, fingerprint_of(ef));
      if (elog_.enabled) log_error(elog_, ef);
      // #210: handle_exception lives on the error resource and nowhere
      // else, so the exception object itself is what crosses over - not
      // a message some resource already made of it.
      if (resource_exception_take(*b->res, &exc_value)) astep.answered = true;
      else astep.shape = AnswerStep::Shape::kStatus;
    }
    switch (astep.shape) {
      case AnswerStep::Shape::kAlready:
        break;
      case AnswerStep::Shape::kLent: {
        const Variants& pv = b->gzip_ok ? b->ok_prefix_vary : b->ok_prefix;
        const Resp& pfx = minor >= 1 ? (persist ? pv.plain : pv.close)
                                     : (persist ? pv.keep : pv.close);
        sink.append(pfx.bytes);
        char cl[40];
        sink.append(cl, http::spell_content_length(cl, lent_len));
        lend_body(st, sink, {{lent, lent_len}, *plan});
        break;
      }
      case AnswerStep::Shape::kGzip: {
        const Resp& prefix_id =
            minor >= 1 ? (persist ? b->ok_prefix_vary.plain : b->ok_prefix_vary.close)
                       : (persist ? b->ok_prefix_vary.keep : b->ok_prefix_vary.close);
        const Resp& prefix_gz =
            minor >= 1 ? (persist ? b->ok_prefix_gzip.plain : b->ok_prefix_gzip.close)
                       : (persist ? b->ok_prefix_gzip.keep : b->ok_prefix_gzip.close);
        assemble_dynamic({prefix_id, prefix_gz, sp.body, accept_gzip && st.packetized, head_only}, sink);
        break;
      }
      case AnswerStep::Shape::kPlain: {
        const Resp& prefix = minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                        : (persist ? b->ok_prefix.keep : b->ok_prefix.close);
        assemble(sink, {prefix, sp.body, head_only});
        break;
      }
      case AnswerStep::Shape::kException: {
        std::string message;
        err_pages_.exception_text(exc_value, message);
        const Variants& pv = store_prefix_[(*idx)[500]];
        const Variants& bv = store_[(*idx)[500]];
        ErrorPages::Fields f;
        f.message = message.data();
        f.message_len = message.size();
        f.fingerprint = ef_hash;
        // A ship build says what was thrown and where the log has the rest; a
        // debug build is already telling you about itself, so the trace goes
        // on the page too.
        if (kDebugBuild) {
          f.backtrace = ef.backtrace;
          f.backtrace_len = ef.backtrace_len;
        }
        const Resp& prefix = minor >= 1 ? (persist ? pv.plain : pv.close)
                                        : (persist ? pv.keep : pv.close);
        const Resp& bodyless = minor >= 1 ? (persist ? bv.plain : bv.close)
                                          : (persist ? bv.keep : bv.close);
        spell_error({prefix, bodyless, 500,
                     err_pages_.media_for(500, vals.accept, vals.accept_len), f, head_only},
                    sink);
        break;
      }
      case AnswerStep::Shape::kStatus: {
        const Variants& sv =
            (head_only && status == 200) ? b->ok_head : store_[(*idx)[status]];
        const Resp& bodyless = minor >= 1 ? (persist ? sv.plain : sv.close)
                                          : (persist ? sv.keep : sv.close);
        // RFC 9110 15: only a 4xx or 5xx has something to explain. A 204,
        // a 304 or a redirect is an answer, and answers carry no page.
        if (status >= 400) {
          const Variants& pv = store_prefix_[(*idx)[status]];
          const ErrorPages::Fields f;
          const Resp& prefix = minor >= 1 ? (persist ? pv.plain : pv.close)
                                          : (persist ? pv.keep : pv.close);
          spell_error({prefix, bodyless, status,
                       err_pages_.media_for(status, vals.accept, vals.accept_len), f, head_only},
                      sink);
        } else if (status == 200 && !head_only && plan != nullptr &&
                   b->konst.body.size() >= kLendFloor) {
          // The konst body is a std::string built at setup and immortal.
          // Nothing for the GC to move or collect, so it is lent as a
          // pointer rather than copied into this connection's sink - a
          // copy gives every stalled reader a private duplicate of the
          // same answer.
          //
          // From kLendFloor up. Below it the whole prebuilt 200 goes into
          // the sink - head, Content-Length and body in one piece - and
          // the round leaves as one send.
          const Resp& pfx = minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                       : (persist ? b->ok_prefix.keep : b->ok_prefix.close);
          sink.append(pfx.bytes);
          char cl[40];
          sink.append(cl, http::spell_content_length(cl, b->konst.body.size()));
          lend_body(st, sink, {{b->konst.body.data(), b->konst.body.size()}, *plan});
        } else {
          sink.append(bodyless.bytes);
        }
        break;
      }
    }
    return astep;
  }

  // RFC 9110 6.3: response.file named a file, so no body is spelled here
  // - the framing goes onto the connection and the reactor drives
  // openat2/statx/read. Answers whether it took the round.
  bool answer_from_file(Round& r, uint16_t status, const std::string& rhdrs);

  // RFC 9110 6.3 / RFC 9111: a mounted archive answers this target, head
  // and body, without the flow or the VM. /error_assets/ resolves against
  // the error archive, everything else against --assets.
  Took answer_from_assets(Round& r, std::string& sink, Plan* plan);
  Took answer_from_docroot(Round& r);
  void file_named_tail(Round& r);

  bool fail(Conn& st, uint16_t code, std::string& out, uint8_t log = 0);
  // response.file's answer, head only - the bytes ride after it as a lent
  // segment. `prebuilt` takes the status straight out of the shared store.
  // The head a served file wears: the status it carries, how many octets
  // it declares, and whether it sends any of them.
  struct FileHead {
    uint16_t status;
    size_t content_length;
    bool bodyless;
  };
  void file_spell(Conn& st, FileHead head);
  void file_prebuilt(Conn& st, uint16_t status_code);
  bool ws_upgrade(Conn& st, const WsUpgrade& up, std::string& sink);

  bool sse_begin(Conn& st, const SseBegin& req, std::string& sink);

  // RFC 7541 6.1/6.2.2: what a prebuilt block says - the status, the
  // Content-Type where the route has one, the Allow a 405 keeps.
  struct H2BlockFields {
    uint16_t status;
    const std::string* ctype = nullptr;
    const std::string* allow = nullptr;
  };
  void h2_build_block(H2Block& b, const H2BlockFields& f);
  bool h2_error_page(const H2ErrorAsk& a, H2ErrorPage& p, H2Answer& out);

  bool h2_begin(Conn& st, std::string& sink);
  bool h2_feed(Conn& st, std::string_view data, Sink out);
  bool h2_error(Conn& st, uint32_t code, std::string& sink);
  void h2_rst(Conn& st, uint32_t id, uint32_t code, std::string& sink);
  // RFC 9110 15.6.1: response.file has no HTTP/2 path yet - a run that
  // named one is refused rather than served the empty body it never meant
  // to send. Its own function because those fifteen lines are not part of
  // answering a stream, and inline they cost h2_answer 952 bytes.
  uint16_t h2_refuse_file(Conn& st, const ReqView* req);
  // RFC 9113 6.2: one HEADERS block as it arrived - the stream it belongs
  // to, whether the peer said that is the end of that stream, and the bytes
  // of the block itself.
  struct H2Headers {
    uint32_t stream_id;
    bool end_stream;
    std::span<const unsigned char> block;
  };
  bool h2_dispatch(Conn& st, const H2Headers& h, std::string& sink);
  // The cold branches of h2_dispatch, out of line: the second HEADERS
  // of a stream and the DATA that ends one both serve the parked
  // stream; :protocol opens a WebSocket.
  struct H2Connect {
    uint32_t stream_id;
    std::string_view method;
    std::string_view protocol;
    std::string_view path;
    const struct phr_header* fields;
    size_t nfields;
    const http::ReqValues* vals;
  };
  static size_t h2_fields_of_parked(const H2Stream& stp, struct phr_header* hv);
  bool h2_serve_parked(Conn& st, H2Stream& stp, std::string& sink, bool complete);
  bool h2_extended_connect(Conn& st, const H2Connect& ask, std::string& sink);
  // A parked stream's request as a view: the target it named, and the
  // ReqView the caller owns for it to point into.
  struct Parked {
    std::string_view target;
    ReqView& view;
    // Where the re-match writes its captures. The view only points at
    // them, so they have to live in the caller's frame, beside the view.
    RouteSpans& spans;
  };
  const ReqView* h2_parked_view(Conn& st, Parked p);
  // What one h2 access line is written from: the facts the stream carried,
  // and the :path they were read beside - which is still live only here.
  struct H2Logged {
    const flow::ReqFacts& facts;
    std::string_view target;
  };
  void h2_log(Conn& st, const H2Logged& l);
  // `target` rides beside `req` because an error answer needs it even
  // when no route matched - a 404 names what was not found, and that is
  // exactly the case where there is no ReqView (#210).
  // RFC 9113 8.1: one stream's request, as much of it as answering needs.
  // Eight arguments travelled together - see #std-first.
  struct H2Request {
    uint32_t stream_id;
    const flow::ReqFacts& facts;
    const http::ReqValues* vals;
    const ReqView* req;
    std::string_view target;
    uint16_t route;
    bool head_only;
  };
  // #30: the walk, and the framing, are two functions - a run can stop
  // between them. One framer serves both paths.
  struct H2Produced;
  void h2_produce(Conn& st, const H2Request& q, bool can_park, H2Produced& p);
  void h2_after_run(Conn& st, const H2Request& q, H2Produced& p, uint16_t status);
  bool h2_answer(Conn& st, const H2Request& q, std::string& sink);
  // #30: which of the two an h2 request takes - the straight answer, or
  // a run that may stop. The resource decides: only one that declared
  // `compute` or `watch` can stop, and only that one pays for a frame.
  // What h2_serve did with the request: answered it into the sink,
  // parked a run for it, or closed the connection.
  enum class H2Served : uint8_t { kAnswered, kParked, kClosed };
  H2Served h2_serve(Conn& st, const H2Request& q, std::string& sink);
  // WHATWG HTML over RFC 9113: what an event stream needs to open on one
  // h2 stream. The request's own bytes, because sse_open runs the
  // resource's initialize and that reads `request`.
  struct H2SseAsk {
    uint32_t stream_id;
    uint16_t route;
    std::string_view target;
    RouteSpans* spans;
    const void* fields;
    size_t nfields;
    const http::ReqValues* vals;
  };
  bool h2_sse_begin(Conn& st, const H2SseAsk& ask, std::string& sink);
  void h2_sse_second(Conn& st, std::string& sink);
  // RFC 8441: a WebSocket on one h2 stream, opened by the extended
  // CONNECT. The same fields the event stream needs, plus what the
  // handshake reads.
  struct H2WsAsk {
    uint32_t stream_id;
    uint16_t route;
    std::string_view target;
    RouteSpans* spans;
    const void* fields;
    size_t nfields;
    const http::ReqValues* vals;
  };
  bool h2_ws_begin(Conn& st, const H2WsAsk& ask, std::string& sink);
  bool h2_frame(Conn& st, const H2Request& q, std::string& sink, H2Produced& p);
  void h2_flush_pending(Conn& st, std::string& sink, Plan* plan);
  void h2_build_asset_blocks(AssetEntry& e);
  void h2_build_asset_shared();
  // RFC 9113 6.1/6.9: one asset answer on one stream - the stream it goes
  // out on, the entry it comes from, the status it carries, whether the
  // request wants the body behind the head, and the half-open window of
  // the wire body this answer covers.
  struct H2Asset {
    uint32_t stream_id;
    const AssetEntry& entry;
    uint16_t status;
    bool head_only;
    size_t win_off;
    size_t win_end;
  };
  bool h2_asset_answer(Conn& st, const H2Asset& a, std::string& sink);

  struct AppSlot {
    const RouteTable* table = nullptr;
    uint16_t base = 0;
    uint16_t count = 0;
    const RouteTable* ws_table = nullptr;
    uint16_t ws_base = 0;
    const RouteTable* sse_table = nullptr;
    uint16_t sse_base = 0;
    // The listener serves TLS: request.base_uri says https.
    bool tls = false;
    // RFC 9110 15.5.14: conf.max_body, in octets.
    size_t max_body = kMaxBodyDefault;
  };

  time_t sec_ = 0;
  std::vector<AppSlot> apps_;
  std::vector<Bundle> bundles_;
  std::vector<const WsResource*> ws_res_;
  std::vector<const SseResource*> sse_res_;
  std::vector<Variants> store_;
  std::vector<Variants> store_prefix_;
  std::array<uint16_t, 600> index_ {};
  ErrorPages err_pages_;
  // Not the operator's --assets: the pictures an error page names, under
  // their own reserved prefix, mounted whether or not anything else is.
  Assets* error_assets_ = nullptr;
  std::vector<H2Block> h2_store_;
  H2Block h2_asset405_;
  H2Block h2_asset406_;
  Assets* assets_ = nullptr;
  // Set only in the standalone tier; null means no docroot answers here.
  const MimeDb* mime_ = nullptr;
  size_t zc_min_ = kZeroCopyDefault;
  size_t map_min_ = kFileMapDefault;
  size_t send_chunk_ = file_send_chunk(60);
  Logger alog_;
  Logger elog_;
  uint16_t alog_status_ = 0;
  size_t alog_bytes_ = 0;
  std::string body_;
  std::string gz_body_;
  // RFC 9110 6.3: the field lines one bound run produced (resource_run
  // fills it); empty keeps every prebuilt path byte-identical.
  std::string rhdrs_;
  char date_[29] = {};
};

// #30: the walk, and then the framing. They are two functions because a
// run can stop between them: a compute task or a watcher parks the run,
// and the answer is framed when it comes back. One framer either way -
// the parked path and the straight path must not spell two different
// answers to the same request.
struct Http1::H2Produced {
  const Bundle* b = nullptr;
  const std::array<uint16_t, 600>* idx = nullptr;
  uint16_t status = 0;
  bool have_body = false;
  bool dynamic = false;
  // What this run lent instead of copying, if anything: not yet owned by
  // a stream, so every path out of the framing still has to place or
  // free it.
  mrb_state* lent_mrb = nullptr;
  mrb_value lent_v = {};
  const char* lent = nullptr;
  size_t lent_len = 0;
  bool lent_have = false;
  // The scratch this answer was spelled into. The straight path hands in
  // the writer's own; a parked run hands in a pair of its own, because
  // the writer's would be written over by the next request.
  std::string* body = nullptr;
  std::string* rhdrs = nullptr;
};
}

#endif
