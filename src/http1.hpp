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

#include <picohttpparser.h>
#include <slipstream_tmpfile.h>

namespace webmachine
{

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
// RFC 9113 5.1.2: one h2 connection may hold this many body files open at
// once. A body over kBodySpill takes a descriptor for as long as the
// stream lives, and a client opens streams as fast as the settings allow.
inline constexpr size_t kH2SpillFilesMax = 16;
// RFC 9112 7.1: the framing a chunked body may spend, in two parts.
//
// The floor is what a body may spend before its content allows any
// of it. 64 KiB covers a chunk extension, a trailer section, and the
// size lines of any body. Framing that carries no content stops here.
//
// The rate is the framing one content octet allows. A chunk of one
// octet is legal, and it spends five framing octets: the size digit,
// CR, LF, then CR and LF after the octet. phr_decode_chunked drops all
// five, and a larger chunk spends fewer per octet. So a rate of five
// lets a body of one-octet chunks with no extension pass this budget.
//
// phr_decode_chunked has a rule of its own. When a buffer ends inside
// the body, it adds the framing it dropped to a count. Once that count
// is over 100 KiB it refuses a body whose content is under a quarter
// of the wire. That rule ends a body of one-octet chunks near 20 KiB
// of content. This budget refuses no body that the decoder accepts,
// and the floor is what this server adds to it.
inline constexpr size_t kChunkFramingFloor = 64u * 1024u;
inline constexpr size_t kChunkFramingPerOctet = 5u;

// RFC-free, this server's own: how much answered content one connection
// or one stream may hold for a peer that is not reading it.
//
// A request and its answer bound each other - one answer per request,
// and the next request waits. A tunnel does not: a websocket's input
// drives its output, an event stream speaks on a clock, and a peer is
// free to send while it reads nothing. The send timeout ends such a
// peer, and at line rate a minute is gigabytes, so this is the ceiling
// until it does. Over it the tunnel ends instead of the process growing.
inline constexpr size_t kTunnelOutCap = 8u * 1024 * 1024;

// RFC 9110 6.4: a request body that lives in a file. Both protocols use
// it: an h1 connection carries one, an h2 stream carries one each,
// because h2 uploads on many streams at the same time.
//
// slipstream_tmpfile made the file, so it has no name: nothing to clean
// up, and nothing another process can open. `fd` of -1 says this body is
// in memory, which is every body under kBodySpill.
//
// What open_file answered: the file is open, the process already holds
// kBodyFilesMax body files, or the platform made no file.
enum class SpillOpen : uint8_t { kOpen, kNoSlot, kNoFile };

struct BodySpill {
    int fd = -1;
    // What reached the file. It is the body's whole length once the body
    // is complete, and request.body reads that many bytes from offset 0.
    size_t written = 0;
    // Whether a run has taken the file into its request view. Until it
    // has, the file is a body still arriving, and closing it would throw
    // away what the run is about to read.
    bool bound = false;
    // RFC-free, this server's own: the octets queued and not yet handed
    // to the ring. The ones the kernel holds are in the reactor's own
    // buffer, not here - this object dies with its connection or its
    // stream, and the kernel writes from the memory it was given.
    std::string pending;
    bool in_flight = false;
    size_t offset = 0;
    bool failed = false;
    // The last octet of this body has been queued. The reactor reads it
    // to know that a drained file is a whole body and not a pause.
    bool ended = false;

    // The file goes back, and so does its slot in the process-wide count.
    // The descriptor holds the last reference to it, so the close frees
    // the blocks - there is no name to unlink. Cold, once per large body,
    // so it stays out of the functions that call it.
    __attribute__((noinline)) void close_file();
    // RFC 9110 6.4: takes a slot in the process-wide count, then makes
    // the file. kNoSlot is load: h1 answers 503, h2 refuses the stream.
    // kNoFile is a 500: the request cannot be answered without its body.
    // Both leave fd at -1 and hold no slot. A file this object still
    // holds goes back first, so the count stays exact. Cold, once per
    // large body, so it stays out of the functions that call it.
    __attribute__((noinline)) SpillOpen open_file();
    // Queue body octets. h1 calls it from the feed, h2 from the DATA
    // frame, and neither one writes: the reactor arms the write through
    // the ring, and the octets wait here until it does.
    //
    // A blocking write(2) on this thread was what this replaces. The file
    // is an O_TMPFILE, so on tmpfs it returned at once and on a disk it
    // did not - and every other connection of this process waited for it.
    //
    // The file dies with the carrier that holds it, however that carrier
    // ends. A move steals the descriptor and leaves the source at -1, so
    // an H2Stream the stream table moves cannot close a file twice. The
    // count follows the descriptor, not the object: a moved-from BodySpill
    // holds no file, so its close_file gives nothing back.
    BodySpill() = default;
    ~BodySpill();
    BodySpill(const BodySpill &) = delete;
    BodySpill &operator=(const BodySpill &) = delete;
    BodySpill(BodySpill &&other) noexcept;
    BodySpill &operator=(BodySpill &&other) noexcept
    {
        if (this == &other)
            return *this;
        close_file();
        fd = other.fd;
        written = other.written;
        bound = other.bound;
        pending = std::move(other.pending);
        in_flight = other.in_flight;
        offset = other.offset;
        failed = other.failed;
        ended = other.ended;
        other.fd = -1;
        other.written = 0;
        other.bound = false;
        other.in_flight = false;
        other.offset = 0;
        other.failed = false;
        other.ended = false;
        return *this;
    }
    // Answers false when an earlier write failed, which is a 500: the
    // request cannot be answered without its body.
    bool take(const char *bytes, size_t count);
    // Is there a write for the reactor to arm? One at a time: the file
    // has one offset, and a second write in flight would need a second.
    bool owes_write() const;
    // Everything this body queued is in the file. A run that reads the
    // body waits for this, because a descriptor that still owes octets
    // answers a short read.
    bool drained() const;
    // The octets the reactor hands the ring. They move into the
    // reactor's own buffer, so the writer may queue more while these
    // fly, and so the kernel never writes from memory this object owns.
    void fly_into(std::string &out_value);
    // What the ring answered, and the buffer it wrote from. A short write
    // leaves the rest at the front of the queue, so the next arm carries
    // it.
    void wrote(ssize_t resource, const std::string &out_value);
};

// RFC 9113 5.1: one entry per stream in a non-idle state. The fields are
// what that state machine names and nothing else: what the stream has
// received, what it still owes, and whether either half is closed.
struct SseStream;
void sse_free(SseStream *sqe);
struct WsConn;
void ws_free(WsConn *conn);

// RFC 9110 6.4: where the octets of a request body go. Two types, one
// API, so the code that fills a body is written once and instantiated
// twice. Neither instantiation tests where the octets belong - the head
// answered that before the first one arrived.
struct MemWriter {
    std::string *mem;
    bool put(const char *bytes, size_t count) const;
};

struct FileWriter {
    BodySpill *spill;
    bool put(const char *bytes, size_t count) const;
};

// What a connection is, named. The state is implied today by which of
// four pointers is not null, and nothing says that they are one
// another's alternatives or that a WebSocket never parses a head again.
// This says it.
//
// It is not the dispatch. nm -S on the host build says a switch on this
// costs 87 bytes in feed_parse and saves nothing - the four pointers
// are adjacent members, so the chain the feed walks is one cache line
// and three predicted tests. The feed keeps them. What this carries is
// the name, the rule about which move is legal, and the check that the
// two agree.
enum class ConnMode : uint8_t { kHead, kAsset, kWs, kSse };

inline constexpr const char *conn_mode_name(ConnMode method)
{
    switch (method) {
        case ConnMode::kHead:
            return "reading request heads";
        case ConnMode::kAsset:
            return "sending an asset";
        case ConnMode::kWs:
            return "a WebSocket";
        case ConnMode::kSse:
            return "an event stream";
    }
    return "unknown";
};

// Which move is legal. A connection reads heads until it becomes
// something else, and only an asset comes back - an upgrade and an
// event stream end with the connection.
inline constexpr bool conn_move_ok(ConnMode from, ConnMode to)
{
    if (from == to)
        return true;
    switch (from) {
        case ConnMode::kHead:
            return true;
        case ConnMode::kAsset:
            return to == ConnMode::kHead;
        case ConnMode::kWs:
            return false;
        case ConnMode::kSse:
            return false;
    }
    return false;
}

// The machine, proved where it is written rather than where it runs.
static_assert(conn_move_ok(ConnMode::kHead, ConnMode::kWs));
static_assert(conn_move_ok(ConnMode::kHead, ConnMode::kSse));
static_assert(conn_move_ok(ConnMode::kHead, ConnMode::kAsset));
static_assert(conn_move_ok(ConnMode::kAsset, ConnMode::kHead));
// An upgraded connection is that protocol until it closes.
static_assert(!conn_move_ok(ConnMode::kWs, ConnMode::kHead));
static_assert(!conn_move_ok(ConnMode::kSse, ConnMode::kHead));
static_assert(!conn_move_ok(ConnMode::kWs, ConnMode::kSse));
// Every state reaches kHead again, or ends the connection.
static_assert(conn_move_ok(ConnMode::kAsset, ConnMode::kHead) &&
              !conn_move_ok(ConnMode::kWs, ConnMode::kHead));

// What one buffer of octets did to a body: there was no body to fill,
// it is still short, it finished it, or the write failed.
// kFailed is the client's framing, 400. kTooLarge is 413. kNoSlot is
// the process at kBodyFilesMax, 503. kFileFailed is a file the server
// could not make or write, 500.
enum class BodyTake : uint8_t { kNone, kMore, kWhole, kFailed, kTooLarge, kNoSlot, kFileFailed };

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
    // What a DATA frame on this stream earns, decided once at the head.
    // The DATA path is per frame, and the answer is the same for every
    // frame of one stream: whether the client declared a length, whether
    // a route matched, and whether that route's resource reads content.
    // Reading it out of the route table again per frame was two loads
    // that always answered the same.
    //
    //   kMem     - a bound resource reads it, and it is still small.
    //   kFile    - the same, and the octets go to a file.
    //   kDrop    - nothing reads it: counted, credited and discarded.
    //
    // A request that declared its length picks kMem or kFile at the head
    // and never changes. A request that declared nothing starts at kMem
    // and moves to kFile at the frame that carries it past kBodySpill.
    // That move happens once per stream, not once per frame.
    enum class Data : uint8_t { kMem, kFile, kDrop };
    Data data = Data::kDrop;
    // RFC 9110 15.5.14: what this stream may carry, in octets. The head
    // wrote it, from the nearest of three limits: the resource, the
    // application, the default. A DATA frame reads it and asks nothing.
    size_t max_body = 0;
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
    const AssetEntry *parked_asset = nullptr;
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
        const AssetEntry *asset = nullptr;
        const char *lent = nullptr; // kLent: the handler's frozen String
        std::string owned;          // kOwned: what flow control could not frame
        // RFC 9113 6.9.1: what has already left, against RFC 9110 8.6's total.
        size_t sent = 0;
        size_t length = 0;
        // No RFC: mruby's GC. Non-null exactly while an unroot is owed, and
        // H2State::content_retire is the one place that clears it, so no
        // value is ever unrooted twice.
        mrb_state *mrb = nullptr;
        mrb_value value = {};
        Src src = Src::kNone;
        // RFC 9113 6.9.1: flow control can cut content across many rounds, so
        // "still owes octets" is what keeps the stream - and the lend - alive.
        bool owes() const
        {
            return src != Src::kNone && sent < length;
        }
        // What flow control has not taken yet.
        size_t owed_bytes() const
        {
            return length > sent ? length - sent : 0;
        }
        void take_asset(const AssetEntry *entry, size_t first, size_t text_end)
        {
            src = Src::kAsset;
            asset = entry;
            sent = first;
            length = text_end;
        }
        void take_lent(mrb_state *mrb, mrb_value lent_value, const char *bytes, size_t count)
        {
            src = Src::kLent;
            lent = bytes;
            sent = 0;
            length = count;
            mrb = mrb;
            lent_value = lent_value;
        }
        void take_owned(const char *bytes, size_t count)
        {
            src = Src::kOwned;
            owned.assign(bytes, count);
            sent = 0;
            length = count;
        }
        // WHATWG HTML: an event stream hands over its next tick while the
        // stream is still sending the last one. What has left already is
        // dropped from the front, so a stream that runs for hours holds only
        // what the window has not taken yet.
        void append_owned(const char *bytes, size_t count)
        {
            if (src != Src::kOwned) {
                take_owned(bytes, count);
                return;
            }
            if (sent != 0) {
                owned.erase(0, sent);
                length -= sent;
                sent = 0;
            }
            owned.append(bytes, count);
            length += count;
        }
        void clear()
        {
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
    WsConn *ws = nullptr;
    // WHATWG HTML: the event stream this h2 stream carries, or nothing.
    // One per stream, because an h2 connection multiplexes them - h1 keeps
    // its one on the connection.
    SseStream *sse = nullptr;
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
    // RFC 9113 8.1.1: how many streams this connection lost to a request
    // that did not keep its own word - a body longer or shorter than the
    // Content-Length it declared. One is an error and costs one stream.
    // A run of them is a peer that spends the server's time on purpose,
    // and the connection ends.
    uint32_t lies = 0;

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
        mrb_state *mrb;
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
    H2State();
    // RFC 9113: the decoder dies with the connection - and so does every
    // lend the streams still hold. h1's ~Conn, one tier down: unconditional,
    // GOAWAY or error or a client that simply left.
    ~H2State();
    H2State(const H2State &) = delete;
    H2State &operator=(const H2State &) = delete;

    // RFC 9113 5.1: a stream in the table is open or half-closed.
    H2Stream *find(uint32_t stream_id);
    // RFC 9113 5.1: a stream the connection must remember.
    H2Stream &open(uint32_t stream_id);
    // RFC 9113 5.1: content leaves the stream when the stream does.
    //
    // Clearing `mrb` here makes a second call a no-op, so no value is
    // unrooted twice. The content is cleared whole, so an asset or an
    // owned buffer cannot outlive the stream that framed it.
    void content_retire(H2Stream &sqe);
    // The release: called where a whole round has drained, so nothing the
    // kernel was handed still points into these Strings.
    void content_drain();
    // RFC 9113 5.1: the number stays, the entry goes.
    void close_stream(uint32_t stream_id);
};
} // namespace webmachine

namespace webmachine
{
namespace wsdeflate
{
inline constexpr uint8_t kMinRawWindowBits = 9;

inline constexpr unsigned char kSyncTail[4] = {0x00, 0x00, 0xff, 0xff};

struct Params {
    bool on = false;
    bool server_no_context_takeover = false;
    bool client_no_context_takeover = false;
    uint8_t server_max_window_bits = 15;
    uint8_t client_max_window_bits = 15;
};

namespace detail
{
// RFC 9110 5.6.3: optional whitespace.
constexpr bool is_ows(char conn)
{
    return conn == ' ' || conn == '\t';
}

// RFC 9110 5.6.2: token, which is what 7692 4.2's params are.
constexpr bool is_tchar(char conn)
{
    return (conn >= 'a' && conn <= 'z') || (conn >= 'A' && conn <= 'Z') ||
           (conn >= '0' && conn <= '9') || conn == '!' || conn == '#' || conn == '$' ||
           conn == '%' || conn == '&' || conn == '\'' || conn == '*' || conn == '+' ||
           conn == '-' || conn == '.' || conn == '^' || conn == '_' || conn == '`' || conn == '|' ||
           conn == '~';
}

// RFC 9110 5.1: case-insensitive equality for an extension parameter name.
bool ci_eq(std::string_view text, std::string_view lit);

// RFC 7692 7.1.2.1: 8..15, no leading zeroes - "08" is a refusal.
bool window_bits(const char *value, size_t count, uint8_t &out_value);
} // namespace detail

// RFC 7692 4.2/5.1: one Sec-WebSocket-Extensions value, answered with the
// first offer this endpoint can accept. Declining is never an error.
// What one negotiation answers: the parameters this endpoint accepted, and
// the Sec-WebSocket-Extensions value to echo back.
struct Negotiated {
    Params &params;
    std::string &echo;
};

bool negotiate(std::string_view value, Negotiated out_value);
// RFC 7692 7: the codec itself lives in wsconn.cpp - it is the only
// file that codes a frame. Params and negotiate stay here because the
// h1 upgrade path negotiates the extension before a WsConn exists.
class Codec;
} // namespace wsdeflate
} // namespace webmachine

namespace webmachine
{
inline constexpr size_t kMaxWsMessageDefault = 64u * 1024;

struct WsConn;

bool ws_wants_deflate(const WsResource *round);

// RFC 6455 4.2.2: what admitting one connection answered - the subprotocol
// to echo back, and the status a refusal carries (0 = admitted).
struct WsAdmit {
    std::string &proto;
    uint16_t &status;
};
WsConn *ws_admit(const WsResource *round, Logger *elog, WsAdmit out_value);

void ws_open(WsConn *conn, const wsdeflate::Params &deflate);

bool ws_feed(WsConn *conn, std::string_view data, std::string &sink);

// RFC 6455 7.1.1: the server closes the connection, and a Close frame goes
// first. True = this call wrote one.
bool ws_going_away(WsConn *conn, std::string &sink);

void ws_free(WsConn *conn);
} // namespace webmachine

namespace webmachine
{
struct SseStream;

SseStream *sse_open(const SseResource *round, Logger *log, uint16_t &code);

bool sse_second(SseStream *sqe, int64_t now_s, std::string &sink);
// WHATWG HTML: the same tick, unframed - what the resource said. h2 puts
// these bytes in DATA frames instead of a chunk.
bool sse_tick(SseStream *sqe, int64_t now_s, std::string &body);

void sse_free(SseStream *sqe);
} // namespace webmachine

namespace webmachine
{
namespace ws
{
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

bool accept_key_compute(const char *key_name, size_t key_len, char out_value[28]);

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
    uint8_t opcode = 0;          // RFC 6455 5.2: Opcode
    uint64_t payload_length = 0; // RFC 6455 5.2: Payload length
    // RFC 6455 5.2: where the four Masking-key octets start, which is where
    // the length encoding ended.
    uint8_t masking_key_at = 0;
    bool fin = false;     // RFC 6455 5.2: FIN
    bool rsv1 = false;    // RFC 6455 5.2: RSV1, negotiated by RFC 7692
    bool control = false; // RFC 6455 5.5: opcode has the high bit
};

// RFC 6455 5.2: how many header octets the next decision needs, given how
// many have arrived. Two to see the length encoding and the mask bit, then
// two or eight more for an extended Payload length, then four for the
// Masking-key. Pure and here, not in the reader, because read_head reads
// all of them unconditionally - so this is the one thing that has to be
// true before read_head may be called at all.
uint8_t header_need(const unsigned char *headers, uint8_t have);

// RFC 6455 5.3: transformed-octet-i = original-octet-i XOR
// masking-key-octet-(i MOD 4).
//
// It copies rather than unmasking in place, because every caller is
// already moving the octets somewhere - the control buffer, the inflate
// window, a test's own buffer - so both happen in one pass.
// `key_at` is i's offset within the frame, so a payload delivered in
// pieces keeps the key aligned across recvs.
struct Mask {
    const unsigned char *key; // the frame's four masking octets
    size_t at;                // how far into the frame the next octet sits
};

void unmask_copy(char *dst, std::string_view src, Mask method);

Head read_head(const unsigned char *headers, bool have_codec);

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
Head::Err admit(const Head &headers, const Message &msg);

// RFC 6455 5.2: what a server frame header says.
struct Frame {
    uint8_t opcode;
    bool fin;
    bool rsv1;
    size_t payload_len;
};
size_t header_build(Frame field, char head[10]);

// RFC 6455 5.5.1: what a Close frame said - the code, and the reason where
// it carried one. 1005 is "the peer named none".
struct Close {
    uint16_t code = 1005;
    std::string_view reason;
};
size_t close_payload_build(Close close, char out_value[125]);
bool close_read(std::string_view payload, Close &out_value);
} // namespace ws
} // namespace webmachine

namespace webmachine
{
struct WsResource;
struct WsConn;
namespace wsdeflate
{
struct Params;
}
WsConn *ws_admit(const WsResource *round, Logger *elog, WsAdmit out_value);
bool ws_wants_deflate(const WsResource *round);
void ws_open(WsConn *conn, const wsdeflate::Params &deflate);
bool ws_feed(WsConn *conn, std::string_view data, std::string &sink);
bool ws_going_away(WsConn *conn, std::string &sink);
void ws_free(WsConn *conn);

struct SseResource;
struct SseStream;
SseStream *sse_open(const SseResource *round, Logger *log, uint16_t &code);
bool sse_second(SseStream *sqe, int64_t now_s, std::string &sink);
// WHATWG HTML: the same tick, unframed - what the resource said. h2 puts
// these bytes in DATA frames instead of a chunk.
bool sse_tick(SseStream *sqe, int64_t now_s, std::string &body);
void sse_free(SseStream *sqe);

struct H2State;
void h2_free(H2State *h2_state);

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
    size_t start = 0;      // RFC 9110 6.4: first byte of the content this
                           // round lends
    size_t give = 0;       // how many - the same word H2SendStep uses
    size_t sent_after = 0; // RFC 9110 8.6: content_sent once it lands
    FileStage next = FileStage::kNone;
    bool head = false;        // RFC 9112 2.1: rides the first round only
    bool release_map = false; // munmap: off the wire, may go back
    bool log = false;         // the one access line of this transfer
    bool clear = false;       // the transfer is over
    bool persist = true;      // RFC 9112 9.3
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
inline constexpr size_t file_send_chunk(int send_timeout_s)
{
    const size_t want =
        static_cast<size_t>(send_timeout_s > 0 ? send_timeout_s : 60) * kSlowClientRate;
    if (want < kFileSendChunkMin)
        return kFileSendChunkMin;
    if (want > kFileSendChunkMax)
        return kFileSendChunkMax;
    return want;
};

inline constexpr uint16_t kNoRoute = 0xffff;

class Http1
{
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
            std::string *sink = nullptr;
            struct Plan *plan = nullptr;
            // RFC 9112 9.3: whether the connection lives past this answer. The
            // round decided it before the run started; `spell_next_round` returns it.
            bool persist = true;
            // #30: which park slot this run took, or -1. The promise is the
            // run's own header, and the resumer reads it there - a connection
            // holds many parked runs and none of them is "the" one.
            int park = -1;

            Run get_return_object()
            {
                return Run{handle::from_promise(*this)};
            }
            // Runs eagerly: a run that never stops must reach its answer inside
            // the call that started it, exactly as resource_run does today.
            std::suspend_never initial_suspend() noexcept
            {
                return {};
            }
            // Suspends at the end so the caller can read `status` off the frame
            // and destroy it deliberately - a self-destroying coroutine would
            // take the answer with it.
            std::suspend_always final_suspend() noexcept
            {
                return {};
            }
            void return_value(uint16_t sqe)
            {
                status = sqe;
                finished = true;
            }
            // A raise is a C++ throw here, and the run frames above already
            // catch it. Rethrowing leaves this frame suspended at
            // its final point, which is where the caller destroys it.
            void unhandled_exception()
            {
                throw;
            }
        };

        Run() = default;
        explicit Run(handle headers) : co(headers)
        {
        }
        Run(const Run &) = delete;
        Run &operator=(const Run &) = delete;
        Run(Run &&other) noexcept : co(other.co)
        {
            other.co = {};
        }
        Run &operator=(Run &&other) noexcept
        {
            if (this != &other) {
                destroy();
                co = other.co;
                other.co = {};
            }
            return *this;
        }
        ~Run()
        {
            destroy();
        }

        // Did it reach an answer, or is it parked on something?
        bool done() const
        {
            return !co || co.promise().finished;
        }
        uint16_t status() const
        {
            return co ? co.promise().status : 0;
        }
        void destroy()
        {
            if (co)
                co.destroy();
            co = {};
        }
        // Handed to whatever will resume it - the reactor keeps this and
        // nothing else, because the handle is the parked run's name. There is
        // no slot table and no tag field to translate.
        handle release()
        {
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
        Run::promise_type *p = nullptr;
        bool await_ready() const noexcept
        {
            return false;
        }
        bool await_suspend(Run::handle headers) noexcept
        {
            p = &headers.promise();
            return true;
        }
        Run::promise_type &await_resume() const noexcept
        {
            return *p;
        }
    };

    // The same door, held open. A coroutine cannot name its own promise,
    // and the run has to write into it before it ever stops: `persist` is
    // the request's answer and the caller reads it off the frame. So this
    // asks for the promise and refuses to suspend - await_suspend saying
    // false means "carry on", which is the standard way to read your own
    // frame without leaving it.
    struct Self {
        Run::promise_type *p = nullptr;
        bool await_ready() const noexcept
        {
            return false;
        }
        bool await_suspend(Run::handle headers) noexcept
        {
            p = &headers.promise();
            return false;
        }
        Run::promise_type &await_resume() const noexcept
        {
            return *p;
        }
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
        // Where the octets of a body go, decided at the head from the
        // declared length. The feed must ask "is this a head or a body" of
        // every buffer that arrives, and this is the answer to that same
        // question: kNone is a head, kMem and kFile are a body and where it
        // lands. So the destination costs no test of its own - it rides in
        // the one the feed could not have skipped.
        enum class Body : uint8_t { kNone, kMem, kFile, kChunkMem, kChunkFile };
        Body body_to = Body::kNone;
        // RFC 9112 7.1: where a chunked body stands between two buffers.
        // A declared length needs no state of its own - content_need is the
        // whole of it - but a chunked body is a small machine, and this is
        // picohttpparser's. It is zero filled before the first octet and
        // consume_trailer is set there, so the trailer section is read and
        // dropped by the decoder.
        struct phr_chunked_decoder chunk = {};
        // What one buffer of a chunked body decodes into. The decoder
        // rewrites what it is given, and the receive buffer holds the
        // pipelined request behind this body, so the octets are copied here
        // first. One connection, one buffer, reused for every buffer of
        // every chunked body it ever reads.
        std::string chunk_buf;
        // RFC 9110 15.5.14: how many octets of this body have arrived. A
        // chunked body has no declared length, so this count is what the
        // limit is held against, and what picks the moment memory becomes
        // a file.
        size_t body_count = 0;
        size_t body_limit = 0;
        // RFC 9112 7.1: the framing octets of a chunked body - every chunk
        // size line and every CRLF the decoder drops. They are not the body,
        // so body_limit never sees them, and a client that sends framing and
        // no content would send it forever.
        size_t chunk_framing = 0;
        // RFC 9112 7.1.1: where the strict walk over the chunk framing
        // stands. picohttpparser decodes the body, and it accepts several
        // chunk-size lines the grammar does not allow, so this server reads
        // the same octets first and holds them to the text. The walk owns no
        // body: it only says yes or no.
        //   kSize      the octets are a chunk-size line
        //   kData      chunk_need octets of content are still to come
        //   kAfterData the CRLF that closes a chunk
        //   kDone      the zero chunk arrived; the trailer is the decoder's
        enum class ChunkScan : uint8_t { kSize, kData, kAfterData, kDone };
        ChunkScan chunk_scan = ChunkScan::kSize;
        size_t chunk_need = 0;
        uint8_t chunk_after = 0;
        std::string chunk_line;
        // RFC 9110 8.3: what this body's head declared, kept while the
        // first octets arrive, because the check that reads it happens
        // after the head is gone from the buffer. Empty = this route asked
        // for no check.
        std::string sniff_type;
        // The first octets of the body, up to what the table reads. They
        // are kept apart from the body itself: the body may be going to a
        // file, and the check must not read it back.
        std::string sniff_head;
        bool sniff_done = false;
        // What this connection is. See ConnMode: the feed still reads the
        // pointers, and this is what a reader, a log line and the debug
        // build's check read instead of guessing from them.
        ConnMode mode = ConnMode::kHead;
        // The only way the state changes. The debug build refuses a move
        // the machine does not have; the ship build stores the byte.
        void become(ConnMode to)
        {
            if (kDebugBuild && !conn_move_ok(mode, to)) {
                std::fprintf(stderr,
                             "webmachine: a connection went from %s to %s, which it cannot\n",
                             conn_mode_name(mode), conn_mode_name(to));
                std::abort();
            }
            mode = to;
        }
        // Do the pointers say what the mode says? The debug build asks once
        // per buffer, so a state that drifted fails a test rather than
        // answering a request wrongly.
        bool mode_agrees() const
        {
            switch (mode) {
                case ConnMode::kHead:
                    return asset == nullptr && websocket == nullptr && sse == nullptr;
                case ConnMode::kAsset:
                    return asset != nullptr && websocket == nullptr && sse == nullptr;
                case ConnMode::kWs:
                    return websocket != nullptr && asset == nullptr && sse == nullptr;
                case ConnMode::kSse:
                    return sse != nullptr && asset == nullptr && websocket == nullptr;
            }
            return false;
        }

        // What must be true of a connection between two buffers, whatever
        // it is doing. The mode machine says what this connection is; these
        // say how its parts stand to one another. The debug build asks all
        // of them once per buffer.
        //
        // What is not here, and why: a parked run is read from the
        // coroutine itself and a file transfer carries its own FileStage,
        // so neither has a second copy that could drift from the first.
        // Only a fact stored twice needs a check that the two agree.
        const char *invariant_broken() const
        {
            // A body with a declared length is owed exactly while a
            // destination is named for it. A chunked body owes octets until
            // its own machine says the last chunk came, so content_need says
            // nothing about it.
            const bool chunked = body_to == Body::kChunkMem || body_to == Body::kChunkFile;
            if (!chunked && (content_need != 0) != (body_to != Body::kNone)) {
                return "octets are owed and no destination is named, or the other way round";
            }
            if (chunked && content_need != 0)
                return "a chunked body counts octets it did not declare";
            // The file was opened before the first octet, at the head.
            if (body_to == Body::kFile && spill.fd < 0)
                return "a body goes to a file that is not open";
            if (body_to == Body::kChunkFile && spill.fd < 0) {
                return "a chunked body goes to a file that is not open";
            }
            // An upgraded connection has no request body left to read: the
            // upgrade is the end of the request that carried it.
            if ((mode == ConnMode::kWs || mode == ConnMode::kSse) &&
                (content_need != 0 || content_skip != 0)) {
                return "an upgraded connection still owes octets of a request body";
            }
            return nullptr;
        }
        // No RFC: a half-open span into the wire body of an asset (see
        // Assets::wire_iov), not into the file - a gzip member's octets are
        // not the stored ones.
        size_t asset_off = 0;
        size_t asset_end = 0;
        // A lent body splits the sink, so the segments around it carry offsets
        // the plan has to claim explicitly: `zc_covered` is how far it got.
        size_t zc_covered = 0;
        H2State *h2 = nullptr;
        const AssetEntry *asset = nullptr;
        WsConn *websocket = nullptr;
        SseStream *sse = nullptr;
        const void *peer = nullptr;
        // No RFC and not the kernel's: "zc" here is the [tune] knob's word,
        // zero_copy_threshold, and it means lent instead of copied - a dynamic
        // body frozen and rooted from the handler's return until the round it
        // belongs to has drained. It is not IORING_OP_SEND_ZC; this tree does
        // not use that opcode anywhere.
        mrb_state *zc_mrb = nullptr;
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
        bool run_parked() const
        {
            return static_cast<bool>(parked.co) && !parked.done();
        }

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
            std::array<mrb_value, kJobSlots> answer_value{};
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
            std::array<Job, kJobSlots> job{};
            // Which value each job of the round answers - kJobNode for a
            // node's own callback. A watcher fills its place here too, and it
            // has no Job: nothing crosses to a worker for it.
            std::array<uint8_t, kJobSlots> job_what{};
            // #30: response.userdata as the worker left it, per job, when the
            // worker changed it. Rooted like an answer, read at the resume.
            std::array<mrb_value, kJobSlots> user_value{};
            std::array<bool, kJobSlots> user_have{};
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
            const Resource *job_res = nullptr;
            // #30: the watcher slot each job of this round waits on, or -1.
            std::array<int, kValueJobs> w_slot{{-1, -1, -1, -1}};
            // The pool had no slot: load, and load passes. 429 with a
            // Retry-After of a few seconds.
            bool compute_task_full = false;
            // The worker ended the task at its max_runtime. Not load: a second
            // attempt costs the same, so 500 and no Retry-After.
            bool compute_task_over_deadline = false;
            // The crossing raised: mruby could not dump the block, or CBOR
            // could not carry the arguments. The round answers 500 and the
            // error log says which.
            bool compute_task_not_crossed = false;
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
        Round *park[kParkSlots] = {};
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
        void park_wants_arming(int slot)
        {
            if (slot < 0 || slot >= kParkSlots)
                return;
            park_owes |= static_cast<uint16_t>(1u << slot);
        }

        // A slot for a run that is stopping, or -1 when this connection
        // holds as many as a tag can name.
        int park_take(Round *round)
        {
            if (park_taken == 0xffffu)
                return -1;
            const int i = __builtin_ctz(static_cast<unsigned>(~park_taken) & 0xffffu);
            park_taken |= static_cast<uint16_t>(1u << i);
            park[i] = round;
            park_gen[i]++;
            return i;
        }
        void park_drop(int slot)
        {
            if (slot < 0 || slot >= kParkSlots)
                return;
            park[slot] = nullptr;
            const uint16_t bit = static_cast<uint16_t>(1u << slot);
            park_taken &= static_cast<uint16_t>(~bit);
            park_owes &= static_cast<uint16_t>(~bit);
        }
        Round *park_at(int slot) const
        {
            if (slot < 0 || slot >= kParkSlots)
                return nullptr;
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
        mrb_state *w_mrb = nullptr;
        mrb_value w_hash = {};
        // Added but not yet on the ring. Http1 cannot arm anything - it has
        // no ring - so it leaves the slot here and the reactor collects it,
        // the same way response.file leaves a path for arm_file_open.
        std::vector<int> w_pending;
        uint8_t listener = 0;
        uint8_t peer_len = 0; // no RFC: the socket's address, already spelled
        bool fresh = true;
        bool packetized = false;
        bool zc_lent = false; // a lend is outstanding right now
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
            std::string pathname;       // openat(dirfd, pathname, flags)
            std::string head;           // RFC 9112 2.1: status-line + fields
            std::string content_type;   // RFC 9110 8.3
            std::string field_lines;    // RFC 9112 5: what the run added
            std::string chunk;          // io_uring_prep_read(sqe, fd, buf, ...)
            std::string method_token;   // RFC 9110 9.1
            std::string request_target; // RFC 9112 3.2
            std::string referer;        // RFC 9110 10.1.3
            std::string user_agent;     // RFC 9110 10.1.5
            size_t buf_filled = 0;      // how much of buf the read put there
            // RFC 9110 8.6: content_length is what Content-Length promised,
            // content_sent what has already gone out. The two being unequal is
            // the only thing that keeps a file alive across rounds.
            size_t content_length = 0;
            size_t content_sent = 0;
            // A mapped file: lent whole, in chunks no bigger than one send can
            // move. Like buf it deliberately survives file_clear() - the SQE
            // still points into it - and it goes back on the kDone round, which
            // is by construction the round after the last lend.
            const char *map_addr = nullptr; // munmap(addr, length)
            size_t map_length = 0;
            bool map_wanted = false;       // no RFC: above file_map_threshold
            int64_t if_modified_since = 0; // RFC 9110 13.1.3
            uint16_t status_code = 0;      // RFC 9110 15
            uint8_t log_flags = 0;         // LogRec::flags, see kLogH2
            FileStage stage = FileStage::kNone;
            bool persist = true;    // RFC 9112 9.3
            bool head_only = false; // RFC 9110 9.3.2
            bool if_modified_since_valid = false;
            // Which form a refusal takes, weighed against the caller's Accept
            // while the request was still in hand.
            int err_media = 0;
            int minor = 1; // RFC 9112 2.3: HTTP-version's
                           // second DIGIT
        };
        FileXfer *file = nullptr;
        // Nothing is owed and nothing is held: the state a fresh connection and
        // a delivered file both stand in. The allocation itself survives - see
        // FileXfer's comment above.
        void file_clear()
        {
            if (file == nullptr)
                return;
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
        void map_release()
        {
            if (file == nullptr || file->map_addr == nullptr)
                return;
            ::munmap(const_cast<char *>(file->map_addr), file->map_length);
            file->map_addr = nullptr;
            file->map_length = 0;
        }
        // The one end of the lend window - drained round, closed connection,
        // dead reactor. Never conditional on the round having succeeded.
        void zc_release()
        {
            // The mapping is not released from here. Which round may hand it back
            // is a decision, and decisions live in file_step(); this function
            // runs before that one and could only guess.
            // h2 lends per stream and hands each back where the stream ends,
            // but the last bytes are still in flight there. This is the point
            // that knows they are not, so the h2 backlog is freed here.
            if (h2 != nullptr)
                h2->content_drain();
            zc_covered = 0;
            zc_split = false;
            if (!zc_lent)
                return;
            zc_lent = false;
            resource_body_unlend(zc_mrb, zc_value);
            zc_mrb = nullptr;
        }
        // #30: take one in. The slot is the watcher's one name - the key it
        // is filed under here and the field its completions carry back - so
        // there is nothing to translate between the ring and the hash.
        // Returns the slot, or -1 when this connection is already holding
        // as many as a tag can name.
        int watchers_add(mrb_state *mrb, mrb_value window)
        {
            if (w_mrb == nullptr) {
                w_hash = mrb_hash_new(mrb);
                mrb_gc_register(mrb, w_hash);
                w_mrb = mrb;
            }
            for (int i = 0; i < static_cast<int>(kMaxWatchers); i++) {
                if (!mrb_nil_p(mrb_hash_get(mrb, w_hash, mrb_int_value(mrb, i))))
                    continue;
                watcher_set_slot(window, i);
                mrb_hash_set(mrb, w_hash, mrb_int_value(mrb, i), window);
                w_pending.push_back(i);
                return i;
            }
            return -1;
        }

        mrb_value watchers_at(int slot) const
        {
            if (w_mrb == nullptr)
                return mrb_nil_value();
            return mrb_hash_get(w_mrb, w_hash, mrb_int_value(w_mrb, slot));
        }

        // Gone for good: cancelled by the caller, then emptied here, so the
        // sweep that comes later finds nothing to free and nothing to cancel
        // a second time.
        void watchers_drop(int slot)
        {
            if (w_mrb == nullptr)
                return;
            const mrb_value window = watchers_at(slot);
            if (mrb_nil_p(window))
                return;
            watcher_disarm(window);
            mrb_hash_delete_key(w_mrb, w_hash, mrb_int_value(w_mrb, slot));
        }

        // #30: let the watchers go. Unrooting the hash is the whole of it -
        // the watchers become collectable, and each one's CDATA destructor
        // is what finally takes its descriptor out of the ring.
        void watchers_release()
        {
            w_pending.clear();
            if (w_mrb == nullptr)
                return;
            mrb_gc_unregister(w_mrb, w_hash);
            w_mrb = nullptr;
            w_hash = mrb_nil_value();
        }
        // The connection itself is ending, and the ring may go before the
        // VM collects the watchers. Each one is emptied here, so its
        // destructor has no ring to cancel on, and then all are let go.
        void watchers_forget()
        {
            if (w_mrb != nullptr) {
                for (int i = 0; i < static_cast<int>(kMaxWatchers); i++) {
                    const mrb_value window = watchers_at(i);
                    if (!mrb_nil_p(window))
                        watcher_disarm(window);
                }
            }
            watchers_release();
        }
        // The Ring resets this; `li` is the App's key to "whose connection is
        // this", `pkt` says whether that listener is TCP.
        void reset(uint8_t listener_index, bool pkt)
        {
            zc_release();
            watchers_release();
            // #80: a run still parked when the peer left. Its frame holds the
            // roots and the round; destroying the frame gives them back (see
            // ParkedRoots in run_parkable), and the park bits are free again.
            parked.destroy();
            h2_parked.clear();
            for (Round *&r : park)
                r = nullptr;
            park_taken = 0;
            park_owes = 0;
            map_release();
            delete file;
            file = nullptr;
            peer_len = 0;
            carry.clear();
            content_skip = 0;
            content_need = 0;
            body_to = Body::kNone;
            chunk = {};
            chunk_buf.clear();
            body_count = 0;
            body_limit = 0;
            chunk_framing = 0;
            chunk_scan = ChunkScan::kSize;
            chunk_need = 0;
            chunk_after = 0;
            chunk_line.clear();
            sniff_type.clear();
            sniff_head.clear();
            sniff_done = false;
            mode = ConnMode::kHead;
            body_hold.clear();
            run_wants_body = false;
            spill.close_file();
            listener = listener_index;
            packetized = pkt;
            fresh = true;
            h2_free(h2);
            h2 = nullptr;
            ws_free(websocket);
            websocket = nullptr;
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
        Conn(const Conn &) = delete;
        Conn &operator=(const Conn &) = delete;

        // The websocket, the stream, the h2 state and a response.file transfer
        // die with the connection.
        ~Conn()
        {
            zc_release();
            map_release();
            watchers_forget();
            delete file;
            h2_free(h2);
            ws_free(websocket);
            sse_free(sse);
        }
    };

    struct AppInput {
        const RouteTable *table = nullptr;
        const Resource *const *resources = nullptr;
        size_t nroutes = 0;
        const RouteTable *ws_table = nullptr;
        const WsResource *const *ws_resources = nullptr;
        size_t ws_nroutes = 0;
        const RouteTable *sse_table = nullptr;
        const SseResource *const *sse_resources = nullptr;
        size_t sse_nroutes = 0;
        bool tls = false;
        // RFC 9110 15.5.14: conf.max_body, in octets. What this application
        // accepts as a request body before it answers 413.
        size_t max_body = kMaxBodyDefault;
    };

    Http1(const AppInput *apps, size_t napps, Assets *assets = nullptr);
    Http1(const RouteTable &table, const Resource *const *resources, size_t nroutes,
          Assets *assets = nullptr);

    // #210: the error pages render in a VM, and this layer is handed one
    // rather than owning it: the h1 model is bytes in, bytes out. A caller
    // that never calls this gets the bodyless statuses.
    void open_error_assets(mrb_state *mrb, Assets *error_assets);

    // A pack that was built again, put in the place of the one this layer
    // was handed. Every prebuilt block h2 keeps per entry belongs to the
    // entry, so this rebuilds them for the new pack and nothing else
    // changes. The old pack is not freed here - a response that is on the
    // wire is still lending its bytes, and the caller owns that decision.
    void swap_assets(Assets *assets);

    // The standalone tier: no app, and the docroot answers what the pack
    // does not. The media-type database is the server's, lent here for the
    // one thing this tier decides that the file machine does not - what a
    // name's Content-Type is.
    void serve_docroot(const MimeDb *mime);

    void clock_tick();

    bool pending(const Conn &conn) const;

    // WHATWG HTML: does this connection carry a source with its own schedule?
    // WHATWG HTML: which connections want a wake every second. h1 carries
    // one event stream on the connection; an h2 connection carries one per
    // stream, so it is asked as soon as any stream has one.
    // RFC 6455 5.1: does this connection carry a tunnel rather than a
    // request and an answer? Such a connection owes no next head, so the
    // head clock says nothing about it.
    bool tunneled(const Conn &conn) const;

    // RFC 6455 7.1.1: this connection ran out of its idle time, and a
    // WebSocket says goodbye with a Close frame before the socket goes.
    // True = something was written and the send carries it.
    bool going_away(Conn &conn, std::string &sink);

    bool timed(const Conn &conn) const;

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
            const char *iov_base;
            size_t off; // not ABI: where in the sink, when iov_base is null
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
        std::string &bytes;
        Plan *plan;
    };
    bool connection_feed(Conn &conn, std::string_view data, Sink out_value);

    // The sink has drained, and this connection may still owe bytes: a
    // stopped run, a file transfer, an event stream, an h2 frame, an
    // asset. This spells the next round of them, and when nothing is owed
    // it takes the next request out of the carry. It answers whether the
    // connection lives past that round.
    bool spell_next_round(Conn &conn, std::string &sink, Plan &plan);

    // #80: the reactor saying a worker or a watcher answered. Only a flag -
    // the run is resumed in `spell_next_round`, where a sink and a plan exist.
    // The worker answered. The bytes come back into the reactor's VM
    // here, which is the only thread that may build a value in it. A
    // worker that raised, or an answer CBOR cannot carry, is nil - the
    // run reads it like any other answer and decides for itself.
    static void compute_task_answered(Conn &conn, int park, int job, const ComputeAnswer &answered);
    // #30: one job of a round answered, whatever answered it.
    static void round_answered(Conn::Round &round, int job, mrb_value value);
    // The job a stopped run left, or nullptr. Taken, not read: the reactor
    // arms it once and the connection stops naming it - exactly file_take.
    // Every worker slot is taken. The run is told rather than the layer
    // inventing a refusal - it answers this the way it answers anything.
    static void compute_task_refused(Conn &conn, int park);
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
    static ComputeRefusal compute_task_refusal(Conn::Round &round);
    // #80: the crossing, done by the frame at the stop. The block becomes
    // an id and the arguments become CBOR. After this nothing of the VM is
    // named, which is what lets a worker touch the result at all.
    // A raise here is the application's and not the run's - the walk is
    // over by now and nothing of it is left to answer one - so the
    // crossing runs under a frame of its own. compute_task_cross is the
    // half that raises.
    bool compute_task_hand_over(Conn &conn, Conn::Round &round, int park, const Resource &resource);
    bool compute_task_cross(Conn &conn, Conn::Round &round, int park, const Resource &resource);
    // #30: the watcher a stopped run left, handed to the connection. The
    // connection files it under a slot and roots it; the reactor arms what
    // `w_pending` names. False when the connection can hold no more, and
    // the run is told the way a full pool tells it.
    static bool watch_hand_over(Conn &conn, Conn::Round &round, int park, const Resource &resource);
    // What one event did to the wait.
    enum class WatchStep : uint8_t {
        kWait,  // the block wants the same thing again
        kRearm, // the block asked for other events
        kDone,  // the block called abort; `answer_value` is its last word
    };
    // #30: one readiness, delivered to the block. The block decides what
    // happens next, and it says so through the watcher: `abort` ends the
    // wait, `events=` changes what to wait for, anything else waits again.
    // The return value never means "keep waiting" - a block may answer nil
    // and mean it.
    static WatchStep watcher_event(Conn &conn, int slot, unsigned revents);
    // The watcher was quiet for as long as it allowed. The block hears
    // `:timeout` and answers whether the wait goes on.
    static WatchStep watcher_deadline(Conn &conn, int slot);
    // What a watcher waits for right now, as poll bits, and how long it
    // may stay quiet. The reactor asks both when it arms one.
    static unsigned watcher_mask(Conn &conn, int slot);
    static int watcher_descriptor(Conn &conn, int slot);
    static void watcher_is_armed(Conn &conn, int slot, struct io_uring *ring, uint64_t poll_tag);
    static void watcher_is_unarmed(Conn &conn, int slot);
    // The tag of the poll in the ring for this watcher, or 0 when none is.
    static uint64_t watcher_poll_tag(Conn &conn, int slot);
    static void watchers_drop_slot(Conn &conn, int slot);
    // A watcher this connection has not armed yet. Taken, not read: the
    // reactor arms it once and the connection stops naming it - exactly
    // file_take and compute_task_take.
    static bool watch_take(Conn &conn, int *slot);
    // Which watcher this connection waits on, or -1.
    // #30: the watcher slot each job of the round waits on, or -1. A
    // round can wait on several at once.
    // The other way round: which job a watcher slot answers, or -1 when
    // this connection is not waiting on it.
    // #30: where the run that owns these watchers is waiting. Told after
    // the park, because only then does the frame hold its own state.
    static void watch_run_is(Conn &conn, Conn::Round &round, Resource::RunState *run);
    // #30: every watcher of this connection that stayed quiet for as long
    // as the watcher itself allowed. The sweep asks once per connection, not once per
    // watcher, and this walks the ones that are armed.
    static size_t watchers_over_deadline(Conn &conn, int64_t now, int *slots, size_t max);
    // The earliest deadline any armed watcher of this connection owes, or
    // 0 when none does. The Ring keeps that one number.
    static int64_t watchers_soonest_deadline(Conn &conn);
    static void watcher_armed_at(Conn &conn, int slot, int64_t index);
    static double watcher_quiet_seconds(Conn &conn, int slot);
    // The work a stopped run left, or false. Taken, not read: the reactor
    // arms it once and the connection stops naming it - exactly file_take.
    // #30: response.userdata for this job, as the crossing left it.
    static std::string_view compute_task_user(const Conn &conn, int park, int job);
    static bool compute_task_take(Conn &conn, int park, int job, unsigned *code, std::string &bytes,
                                  double *deadline);
    // response.file, the reactor's half. A bound run may name a file instead
    // of spelling a body; opening it is disk work, so it never happens inside
    // the run. These five are the whole contract with the Ring - it drives
    // openat2/statx/read through the ring and hands each result back here,
    // and the answer reaches the wire through `spell_next_round` like every other
    // continuation. Any refusal - a miss, a directory, a resolve flag
    // catching an escape - lands as the same 404 file_reject spells.
    const char *file_take(Conn &conn);
    // The question file_take answers, asked without a call. The reactor
    // asks it on every recv and every round, and the answer is almost
    // always no: file_take lives in another translation unit, so the no
    // cost a call and a return. Measured at 0.38% of a whole h1 run.
    static bool file_waiting(const Conn &conn);
    // The same, for the work a stopped run left. arm_compute_task built a
    // std::string before it asked. Measured at 0.45%.
    static bool compute_task_waiting(const Conn &conn);
    static uint8_t park_generation(const Conn &conn, int park);
    // The next parked run with a job to arm, or false. Taken, not read -
    // the same shape as file_take and watch_take.
    static bool park_take_pending(Conn &conn, int *park);
    // RFC 9110 6.4: the request body of this connection that still owes
    // octets to its file. h1 has one spill; an h2 connection has one per
    // stream, and one write flies at a time because the answer names a
    // connection and not a stream.
    //
    // The reactor asks this on every recv and every round, the same way
    // it asks file_waiting, and the answer is no for every connection
    // that is not taking an upload.
    static BodySpill *spill_waiting(Conn &conn);
    static BodySpill *spill_waiting_h2(Conn &conn);
    // What the ring answered for the write it armed. The body may be
    // whole now, and then the run that stopped for it is ready.
    void spill_wrote(Conn &conn, ssize_t resource, const std::string &out_value);
    void file_reject(Conn &conn);
    void file_error(Conn &conn, const char *why);
    bool file_stat(Conn &conn, const struct statx &stx, size_t *want);
    char *file_buffer(Conn &conn, size_t count);
    void file_ready_now(Conn &conn, size_t count);
    void file_mapped(Conn &conn, const char *bytes, size_t count);
    // Is a round waiting for `spell_next_round` to run? kDone counts: it puts nothing on
    // the wire, but it is the round that hands the mapping back and writes
    // the access line, so nothing may go idle in front of it.
    // RFC 9110 6.4: one buffer of a body into the place the head chose.
    // W is MemWriter or FileWriter, and this is the only code either one
    // ever runs - which is why it holds no test about where the octets
    // belong.
    // RFC 9112 7.1: one buffer of a chunked body, into the place the head
    // chose. W is MemWriter or FileWriter, the same two the declared-length
    // reader uses.
    //
    // phr_decode_chunked does the decoding. It is picohttpparser's, which
    // this server already trusts for every request head, and it holds its
    // own state across buffers - a buffer may end inside the size, inside
    // the data or between the CR and the LF, and the decoder remembers
    // where it was. consume_trailer is set at the head, so the trailer
    // section is read and dropped here rather than in code of ours.
    //
    // The decoder rewrites the buffer it is given, so it cannot have the
    // receive buffer: a pipelined request sits behind this body and the
    // parse reads it from there. It gets Conn::chunk_buf instead, which
    // is this connection's and is reused, so a body of any size takes one
    // allocation and not one per buffer.
    //
    // kFailed is the client's fault and the caller answers 400. A writer
    // that refuses its octets is kFileFailed, the server's own 500. Both
    // end the connection.
    //
    // Out of line on purpose: a chunked request is the rare one, and
    // inlined twice it put 379 bytes of decoder into feed_parse, which
    // every request walks. nm -S on the host build decided it.
    // RFC 9110 5.6.2: the octets a token may carry.
    static bool chunk_tchar(char conn);

    static bool chunk_hex(char conn);

    // RFC 9112 7.1.1: one chunk-size line, without its CRLF.
    //
    //   chunk-size = 1*HEXDIG
    //   chunk-ext  = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
    //
    // BWS is whitespace a sender must not send and a recipient may accept,
    // and it stands only where the rule puts it: around the semicolon and
    // around the equals. Whitespace anywhere else belongs to no rule, so a
    // size with a space behind it and no extension is refused. An extension
    // needs its semicolon, a semicolon needs its name, and an equals needs
    // its value. A quoted value may hold anything, the semicolon included,
    // and a backslash inside it quotes the octet behind it.
    //
    // Cold: once per chunk header of a chunked body, which is the rare
    // request, and out of line because take_chunked is out of line already.
    __attribute__((noinline)) static bool chunk_size_line_ok(const char *bytes, size_t count);

    // RFC 9112 7.1.1: the same octets the decoder is about to read, held to
    // the grammar first. picohttpparser accepts `2 erfrferferf`, `2;`, `a `
    // and a bare CR inside the line, and answers a size for each, so a
    // server that wants the grammar has to say so itself.
    //
    // The walk keeps its own place, because the decoder's is not reachable
    // and one buffer may carry several chunks. It never copies the body -
    // only a size line that a buffer cut in half.
    __attribute__((noinline)) static bool chunk_lines_ok(Conn &conn, const char *data,
                                                         size_t length);

    template <class W>
    __attribute__((noinline)) static BodyTake take_chunked(Conn &conn, W window, const char *&data,
                                                           size_t &len)
    {
        if (len == 0)
            return BodyTake::kMore;
        // RFC 9112 7.1.1: the grammar first, because the decoder is lenient
        // about it and a chunk reader that takes sizes outside the grammar is
        // where request smuggling keeps being found.
        if (mrb_unlikely(!chunk_lines_ok(conn, data, len)))
            return BodyTake::kFailed;

        conn.chunk_buf.assign(data, len);
        size_t decoded = conn.chunk_buf.size();
        const ssize_t rest = phr_decode_chunked(&conn.chunk, conn.chunk_buf.data(), &decoded);
        if (mrb_unlikely(rest == -1))
            return BodyTake::kFailed;
        // RFC 9110 15.5.14: the count is the only length a chunked body
        // has, so the limit is held against it, here.
        if (mrb_unlikely(conn.body_count + decoded > conn.body_limit))
            return BodyTake::kTooLarge;
        if (mrb_unlikely(decoded != 0 && !window.put(conn.chunk_buf.data(), decoded))) {
            return BodyTake::kFileFailed;
        }
        conn.body_count += decoded;
        // Everything this call was given is spoken for: what the decoder
        // read, and the framing it dropped. What it did not read is a
        // pipelined request, and the cursor stops in front of it.
        const size_t used = rest < 0 ? len : len - static_cast<size_t>(rest);
        // RFC 9112 7.1: what this call used and did not deliver is framing.
        // The budget is kChunkFramingFloor plus kChunkFramingPerOctet for
        // every content octet of this body. body_count already holds this
        // call's octets. A body in one-octet chunks passes, and framing
        // that carries no content stops at the floor.
        conn.chunk_framing += used - decoded;
        if (mrb_unlikely(conn.chunk_framing >
                         kChunkFramingFloor + conn.body_count * kChunkFramingPerOctet)) {
            return BodyTake::kFailed;
        }
        data += used;
        len -= used;
        // The one move: this body has outgrown memory. What memory holds
        // goes to the file, and every octet after it is a file write. Once
        // per body, never per buffer.
        if (mrb_unlikely(conn.body_to == Conn::Body::kChunkMem &&
                         conn.body_hold.size() >= kBodySpill)) {
            const SpillOpen opened = conn.spill.open_file();
            if (mrb_unlikely(opened != SpillOpen::kOpen)) {
                return opened == SpillOpen::kNoSlot ? BodyTake::kNoSlot : BodyTake::kFileFailed;
            }
            if (!conn.spill.take(conn.body_hold.data(), conn.body_hold.size()))
                return BodyTake::kFileFailed;
            conn.body_hold.clear();
            conn.body_hold.shrink_to_fit();
            conn.body_to = Conn::Body::kChunkFile;
        }
        if (rest < 0)
            return BodyTake::kMore;
        conn.body_to = Conn::Body::kNone;
        return BodyTake::kWhole;
    }

    template <class W>
    static BodyTake take_body(Conn &conn, W window, const char *&data, size_t &length)
    {
        const size_t take = length < conn.content_need ? length : conn.content_need;
        if (mrb_unlikely(!window.put(data, take)))
            return BodyTake::kFileFailed;
        conn.content_need -= take;
        data += take;
        length -= take;
        if (conn.content_need != 0)
            return BodyTake::kMore;
        conn.body_to = Conn::Body::kNone;
        return BodyTake::kWhole;
    }

    // RFC 9110 6.4: a body this connection stops reading at a refusal.
    // The destination is forgotten, the memory is freed, and the file
    // is closed here and not at the next accept into this slot. A body
    // that already spilled would keep its descriptor open until then.
    //
    // Out of line on purpose: four refusal arms in feed_parse spell these
    // five stores, and feed_parse is the function every request walks.
    __attribute__((noinline)) static void drop_body(Conn &conn);

    static bool file_answerable(const Conn &conn);
    // #36: a run of this connection stopped for the request body, and the
    // body is whole. Its answer owes the ring no completion - the octets
    // came in on the receive that just fed the parser - so nothing else
    // would ever come back to collect it. The reactor asks this instead,
    // the way it asks file_answerable.
    static bool run_resumable(const Conn &conn);
    // 0 = do not map; otherwise the exact length to map. One question, one
    // answer - the split that made the read path ask "map?" and then use the
    // map's length to read with.
    static size_t file_map_len(const Conn &conn);
    // Which shape a resource's answer takes. One value, decided once, so
    // the writer and the access line below cannot disagree about what went
    // out.
    struct AnswerStep {
        enum class Shape : uint8_t {
            kAlready,   // the dynamic-head branch already spelled it
            kLent,      // a lent body behind the 200 prefix
            kGzip,      // conneg between identity and gzip
            kPlain,     // a copied body behind the 200 prefix
            kException, // a 500 the resource spelled itself (may demote)
            kStatus     // a prebuilt status line and nothing else
        };
        Shape shape = Shape::kStatus;
        size_t body_len = 0; // what the access line counts
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
    static AnswerStep answer_step(const AnswerFacts &field);

    // RFC 9113 6.9.1: what one stream may put on the wire this round. Both
    // windows, what is left of the body, and - for a copied buffer only -
    // the delivery chunk. This was the same twenty lines three times over,
    // once per source, each computing the budget again and each writing in
    // the middle of the arithmetic.
    // How many bytes of the stream's body go out this round. It no longer
    // picks among sources - there is one - so it decides a count and nothing
    // else; where the bytes come from is H2Stream::Body's business.
    struct H2SendStep {
        size_t start = 0;  // first byte of the body this round frames
        size_t give = 0;   // how many bytes it may frame
        size_t total = 0;  // the body's length, so END_STREAM is a comparison
        bool ends = false; // give reaches the last byte
    };
    // What the connection allows this round: what is left of its own flow
    // window, and the largest copy this round is willing to make.
    struct RoundRoom {
        int64_t conn_window;
        size_t chunk;
    };
    static H2SendStep h2_send_step(const H2Stream &sqe, RoundRoom room);

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
        const http::ReqValues &vals;
    };
    static AssetStep asset_step(const AssetEntry &entry, const RangeAsk &request_ask);

    // The next round of a transfer, computed and not performed.
    //
    // Defined here, not in a .cpp: `spell_next_round` lives in another translation unit
    // and this build has no LTO, so a definition over there would be a real
    // call with a 48-byte return through memory (SysV returns anything past
    // 16 bytes that way). Inlined, the FileStep never exists - the compiler
    // keeps its fields in registers. Purity only pays where the compiler can
    // see it.
    static FileStep file_step(const Conn::FileXfer &one, size_t chunk);
    // The one place a transfer's state changes as a round is delivered.
    void file_apply(Conn &conn, const FileStep &step);
    // The single access line of a transfer, with the bytes that really went
    // out. Called on the kDone round, or by file_abandon when a connection
    // dies under one; the stage is what keeps it from happening twice.
    void file_log(Conn &conn);
    // A connection closing under a transfer still owes its access line.
    void file_abandon(Conn &conn);
    // Nothing owed, nothing on the wire: give the read buffer back, or a slot
    // that once served a big file would hold those bytes for the process's
    // life. The Ring calls this only where both are true.
    static void file_release(Conn &conn);

    // The App formats lines; the Ring flushes the buffer. Opt-in.
    Logger *access_log();
    // The only way an access line is ever built.
    void enable_access_log();
    // The second stream: its own socket, its own daemon, its own file.
    Logger *error_log();
    // The only way an error record is ever built.
    void enable_error_log();
    // [tune] zero_copy_threshold, once, before the first accept.
    void set_zero_copy_threshold(size_t count);

    // [tune] file_map_threshold, once, before the first accept. 0 = never map.
    void set_file_map_threshold(size_t count);
    // The Ring owns the send clock, so the Ring is what tells this layer how
    // much one send may carry - one rule, one place.
    void set_send_timeout(int secs);

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
        const AppSlot &slot;
        int route;
        std::string_view method;
        std::string_view path;
        const RouteSpans &spans;
        const void *hdrs; // struct phr_header[]; the framer's header is not here
        size_t nhdr;
        int minor;
        flow::Method m;
        const http::ReqValues &vals;
        uint8_t lflags;
    };

    struct WsUpgrade {
        const AppSlot &slot;
        int route;
        std::string_view path;
        const RouteSpans &spans;
        std::string_view key;
        const void *hdrs; // struct phr_header[]; the framer's header is not here
        size_t nhdr;
        const http::ReqValues &vals;
        std::string_view rest; // bytes after the head, already in hand
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
        const char *body = nullptr;
        size_t blen = 0;
        const H2Block *blk = nullptr;
    };

    struct Bundle;

    // And what spelling an error answer needs to know first: the status it
    // carries, the words #210 filled in for it, the header values the request
    // frame still holds (for Accept), and the route whose Allow a 405 keeps.
    struct H2ErrorAsk {
        uint16_t status;
        const ErrorPages::Fields &fields;
        const http::ReqValues *vals;
        const Bundle *bundle;
    };

    struct Bundle {
        flow::KonstSet konst;
        // RFC 9110 12.5.1: what c4 weighs an Accept against - the media type
        // without the charset parameter konst.content_type grows here, and
        // present even for the default route, which has no Resource behind it.
        std::string accept_type;
        const Resource *res = nullptr;
        std::array<uint16_t, 600> index{};
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

    void http1_build_all(const AppInput *apps, size_t napps);
    // RFC 9112 9.3: one status prebuilt - the code, the fields that always go
    // with it, the body it carries where it carries one, the Date bytes laid
    // down (a placeholder at boot; the second's own from then on), and the
    // Connection field of the spelling being built.
    struct Prebuilt {
        uint16_t status;
        const char *extra;
        const char *body;
        const char *date;
        const char *conn = "";
    };
    static void build_variants(Variants &value, Prebuilt bytes);
    static void build_one_variant(Resp &round, Prebuilt bytes);
    static void copy_without_tail(const Resp &src, Resp &dst, size_t cut);
    // RFC 9112: a head that stops before Content-Length, for a body the run
    // has yet to produce - the status line, the route's own fields, whatever
    // Vary / Content-Encoding applies, and the Connection field of the
    // spelling being built.
    struct OpenPrefix {
        const char *status_line;
        const std::string &extra;
        const char *enc;
        const char *conn = "";
    };
    static void build_open_prefixes(Variants &value, OpenPrefix bytes);
    static void build_open_prefix(Resp &round, OpenPrefix bytes);
    // RFC 9113 6.2: one whole HEADERS frame for the cache to replay - the
    // route's prebuilt block, the per-answer fields, and the date.
    struct CachedHead {
        const H2Block &block;
        std::span<const unsigned char> fields;
        std::span<const unsigned char> date;
    };
    static void cache_headers(std::string &out_value, const CachedHead &head);
    // WHATWG HTML: an event stream's one access record. SseLine is what the
    // seven arguments were - see #std-first.
    struct SseLine {
        std::string_view method;
        std::string_view path;
        const http::ReqValues &vals;
        uint16_t status;
        uint8_t lflags;
    };
    static void log_sse(Logger &logger, const Conn &conn, const SseLine &line);
    // What one prebuilt status says beyond its status line: the fields that
    // always go with it, and the body it carries where it carries one.
    struct StatusText {
        const char *extra;
        const char *body;
    };
    void build_status(uint16_t status, StatusText text);
    void status_line_is_stocked(bool have[600], uint16_t sqe);
    void build_bundle(Bundle &block, const Resource *resource);
    static void patch_date(Variants &value, const char *core);
    // RFC 9112: one prebuilt head and the body behind it - a HEAD request
    // takes the same head and none of the bytes.
    struct Assembled {
        const Resp &prefix;
        std::string_view body;
        bool head_only;
    };
    static void answer_assemble(std::string &sink, const Assembled &answer);
    bool feed_parse(Conn &conn, std::string_view data, Sink out_value);
    // The cold branches of feed_parse, out of line: the protocol decision
    // on a fresh connection, and a head that upgrades or opens a stream.
    enum class Preface : uint8_t { kH1, kH2, kWait, kRefused };
    Preface h1_preface(Conn &conn, const char *data, size_t length, std::string &sink,
                       size_t *consumed);
    struct H1Head {
        std::string_view method;
        std::string_view path;
        int minor;
        const struct phr_header *headers;
        size_t num_headers;
        const flow::ReqFacts &facts;
        const http::ReqValues &vals;
        uint8_t lflags;
        bool wants_ws;
        int ws_version;
        const char *ws_key;
        size_t ws_key_len;
        const char *rest;
        size_t rest_len;
    };
    bool h1_upgrade_or_stream(Conn &conn, const H1Head &headers, std::string &sink, bool *lives);
    static void sink_claim(Conn &conn, const std::string &sink, Plan &plan);
    // The bytes one answer lends rather than copies, and the plan they are
    // lent into.
    struct Lending {
        std::string_view body;
        Plan &plan;
    };
    static void body_lend(Conn &conn, std::string &sink, Lending lend);
    // RFC 9110 12.5.3/12.5.5: what a dynamic 200 chooses between - the two
    // prebuilt prefixes, whether gzip is on the table at all (the peer
    // accepts it and this connection is packetized), and whether the request
    // wants the body behind the head.
    struct DynamicBody {
        const Resp &prefix_id;
        const Resp &prefix_gz;
        // The bytes the run spelled. Handed in, never read off a member: a
        // parked run writes into its own string, and the writer's own is
        // already carrying the next request by the time this runs.
        const std::string &body;
        bool may_gzip;
        bool head_only;
    };
    void assemble_dynamic(const DynamicBody &dynamic_body, std::string &sink);
    // RFC 9112 9.3: one prebuilt status in its three connection spellings.
    const Variants &variants(uint16_t status) const;
    // The same status without its Content-Length and terminator: what an
    // error answer that has a page puts its own two fields behind.
    const Variants &prefixes(uint16_t status) const;
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
        const Resp &prefix;
        const Resp &bodyless;
        uint16_t status;
        int media;
        const ErrorPages::Fields &fields;
        bool head_only;
    };
    void spell_error(const ErrorAnswer &entry, std::string &sink);
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
        // The body, when the request carried one in the same buffer and a
        // callback declared that it reads one. A resource that declared no
        // reader is given a view with no content at all, so this stays
        // empty and nothing is copied - see bound_prepare.
        std::string content;
        http::ReqValues vals{};
        RouteSpans spans{};
        ReqView rv{};
        std::unique_ptr<struct phr_header[]> fields;
        size_t nfields = 0;

        Held();
        ~Held();
        Held(Held &&) noexcept;
        Held &operator=(Held &&) noexcept;
        Held(const Held &) = delete;
        Held &operator=(const Held &) = delete;

        // One run of bytes the copy replaces, and how far it moved. A view
        // can point into two of them: the head, and - h2 only - the request
        // target, which a parked stream keeps apart from its fields.
        struct Span {
            const char *at = nullptr;
            size_t len = 0;
            ptrdiff_t delta = 0;
            // True when this span owned the pointer and moved it. One past the
            // end belongs to the span as well: an empty piece at the end of it
            // is spelled that way.
            bool move(const char *&bytes) const
            {
                if (at == nullptr || bytes == nullptr || bytes < at || bytes > at + len)
                    return false;
                bytes += delta;
                return true;
            }
        };

        // Copy the head and re-point `from` at the copy. After this the
        // provided buffer may go back to the kernel, which is the whole
        // point - see Run.
        //
        // `target` is the request target this frame owns, for a caller whose
        // view points at a target outside the head: h2 gives a parked stream
        // its fields from one buffer and its target from another, and the
        // route captures point into the target. Null says the target lies in
        // the head, which is h1 and an h2 head this dispatch decoded.
        void hold(const char *head_at, size_t head_len, const ReqView &from,
                  const std::string *target);
    };

    // What one request round already knows by the time the head is parsed.
    // A step that leaves the straight line takes this instead of twenty
    // arguments - which is what made those steps stay inline before.
    struct Round {
        Conn &st;
        const Bundle *b;
        const char *view;
        size_t viewlen;
        size_t off;
        size_t head_len;
        bool in_place;
        const char *method;
        size_t method_len;
        const char *path;
        size_t path_len;
        int minor;
        bool persist;
        bool head_only;
        size_t content_length;
        uint8_t lflags;
        const flow::ReqFacts &facts;
        const http::ReqValues &vals;
    };

    // What a step that may take the round over answers with.
    enum class Took : uint8_t {
        kNo,          // not this step's request; the straight line continues
        kNextRequest, // answered, and the pipeline may hold another
        kOwed,        // answered so far as it can be; bytes are still owed
        kClose        // answered, and the connection ends
    };

    // #80: what the bound answer needs beyond the Round. It cannot sit
    // inline in feed_parse: a run that parks returns out of it and comes
    // back later, which a block in a loop body cannot do. A dozen values
    // that travel together are a type, like Spelling below.
    struct BoundAsk {
        const void *fields;
        size_t nfields;
        const RouteSpans &spans;
        const RouteTable *table;
        int route;
        Plan *plan;
        std::string &sink;
        // Where the run writes its body and its field lines. They used to be
        // two Http1 members, reused request after request. A run that parks
        // may not share them: the next request on this connection's ring
        // would write over what the parked one still owes, so a parked run
        // brings its own and the straight path keeps handing in the pair it
        // always reused.
        std::string &body;
        std::string &rhdrs;
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
        const char *lent = nullptr;
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
    void bound_prepare(Round &round, const BoundAsk &request_ask, BoundPrep &prep);

    // #80: everything a stopped run has to keep about the request, by
    // value. The Round it is built from holds references into feed_parse's
    // frame, and that frame is gone the moment the run stops - so the
    // coroutine takes copies and re-seats them at `head` once hold() has
    // run.
    struct BoundStart {
        const Bundle *b;
        const char *head_at; // the request head's first byte, for hold()
        const char *view;
        size_t viewlen;
        size_t off;
        size_t head_len;
        const char *method;
        size_t method_len;
        const char *path;
        size_t path_len;
        size_t content_length;
        const void *fields;
        size_t nfields;
        RouteSpans spans;
        const RouteTable *table;
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
            // #54: the request as the dispatch saw it, and the bytes its
            // fields point into. The run copies both into its own frame
            // before it can stop, the same way h1 holds its head, and after
            // that the decode buffer may be reused by the next dispatch.
            //
            // Null = a konst route or an asset: nothing that can stop, and
            // nothing that reads a field.
            const ReqView *view = nullptr;
            const char *head_at = nullptr;
            size_t head_len = 0;
        };
        H2Start h2{};
    };
    Run run_parkable(Conn &conn, RunStart sqe, std::string *sink, Plan *plan);
    // What one such round leaves for the parse to do next.
    enum class ComputeRound : uint8_t {
        kNext,   // answered here; read the next request out of this buffer
        kParked, // stopped; what is left waits in the carry
        kClosed, // the answer was the connection's last
    };
    // The whole compute round, OUT of feed_parse. It is cold: a resource
    // that never said `compute` does not reach it, and feed_parse is the
    // hottest function in the server. Inlined
    // here it was paid for by every request that never
    // ran a compute task.
    __attribute__((noinline)) ComputeRound start_compute_round(Conn &conn, const BoundStart &sqe,
                                                               std::string *sink, Plan *plan,
                                                               size_t &off);

    // kOwed = nothing is answered yet: the body is still coming, or a file
    // is being fetched through the ring.
    Took answer_bound(Round &round, const BoundAsk &request_ask, BoundOut &out_value);
    // The half after the walk. Reached from answer_bound and, once a run
    // can park, from the coroutine a promising resource runs through.
    Took bound_finish(Round &round, const BoundAsk &request_ask, BoundOut &out_value);

    // #80: what the answer switch needs beyond the Round - the sink it
    // writes to, the plan a lend rides out on, and what the run left
    // behind. A struct because these travelled together as nine
    // arguments, and #std-first says that is a type.
    struct Spelling {
        std::string &sink;
        Plan *plan;
        uint16_t status;
        const char *lent;
        size_t lent_len;
        bool answered;
        bool have_body;
        bool accept_gzip;
        const std::array<uint16_t, 600> *idx;
        // Same reason as DynamicBody::body: the run that spelled these bytes
        // may be one that stopped, and then they are not the writer's.
        const std::string &body;
    };
    // #80: the answer, spelled. Split out of feed_parse so the bound tier can
    // reach it from inside a coroutine while the konst tier keeps calling it
    // straight - a run that can never stop must not pay for a frame.
    // Returns the step it took, because the access line counts what it wrote.
    AnswerStep spell_answer(Round &round, Spelling sp);

    // RFC 9110 6.3: response.file named a file, so no body is spelled here
    // - the framing goes onto the connection and the reactor drives
    // openat2/statx/read. Answers whether it took the round.
    bool answer_from_file(Round &round, uint16_t status, const std::string &rhdrs);

    // RFC 9110 6.3 / RFC 9111: a mounted archive answers this target, head
    // and body, without the flow or the VM. /error_assets/ resolves against
    // the error archive, everything else against --assets.
    Took answer_from_assets(Round &round, std::string &sink, Plan *plan);
    Took answer_from_docroot(Round &round);
    void file_named_tail(Round &round);

    bool connection_fail(Conn &conn, uint16_t code, std::string &out_value, uint8_t log = 0);
    // response.file's answer, head only - the bytes ride after it as a lent
    // segment. `prebuilt` takes the status straight out of the shared store.
    // The head a served file wears: the status it carries, how many octets
    // it declares, and whether it sends any of them.
    struct FileHead {
        uint16_t status;
        size_t content_length;
        bool bodyless;
    };
    void file_spell(Conn &conn, FileHead head);
    void file_prebuilt(Conn &conn, uint16_t status_code);
    bool ws_upgrade(Conn &conn, const WsUpgrade &up, std::string &sink);

    bool sse_begin(Conn &conn, const SseBegin &request, std::string &sink);

    // RFC 7541 6.1/6.2.2: what a prebuilt block says - the status, the
    // Content-Type where the route has one, the Allow a 405 keeps.
    struct H2BlockFields {
        uint16_t status;
        const std::string *ctype = nullptr;
        const std::string *allow = nullptr;
    };
    void h2_build_block(H2Block &block, const H2BlockFields &field);
    bool h2_error_page(const H2ErrorAsk &answer, H2ErrorPage &bytes, H2Answer &out_value);

    bool h2_begin(Conn &conn, std::string &sink);
    bool h2_feed(Conn &conn, std::string_view data, Sink out_value);
    bool h2_error(Conn &conn, uint32_t code, std::string &sink);
    void h2_reset_stream(Conn &conn, uint32_t stream_id, uint32_t code, std::string &sink);
    bool h2_count_lie(Conn &conn, uint32_t stream_id, std::string &sink);
    // RFC 9110 15.6.1: response.file has no HTTP/2 path yet - a run that
    // named one is refused rather than served the empty body it never meant
    // to send. Its own function because those fifteen lines are not part of
    // answering a stream, and inline they cost h2_answer 952 bytes.
    uint16_t h2_refuse_file(Conn &conn, const ReqView *request);
    // RFC 9113 6.2: one HEADERS block as it arrived - the stream it belongs
    // to, whether the peer said that is the end of that stream, and the bytes
    // of the block itself.
    struct H2Headers {
        uint32_t stream_id;
        bool end_stream;
        std::span<const unsigned char> block;
    };
    bool h2_dispatch(Conn &conn, const H2Headers &headers, std::string &sink);
    // RFC 9113 5.1.2, 8.7: the file for a body that starts in one, behind
    // the two ceilings that refuse it. Answers false when the stream was
    // refused. Out of line: once per large body, never per request.
    bool h2_body_file_open(Conn &conn, H2Stream &stx, uint32_t stream_id, std::string &sink);
    // The cold branches of h2_dispatch, out of line: the second HEADERS
    // of a stream and the DATA that ends one both serve the parked
    // stream; :protocol opens a WebSocket.
    struct H2Connect {
        uint32_t stream_id;
        std::string_view method;
        std::string_view protocol;
        std::string_view path;
        const struct phr_header *fields;
        size_t nfields;
        const http::ReqValues *vals;
    };
    static size_t h2_fields_of_parked(const H2Stream &stream, struct phr_header *header_vector);
    bool h2_serve_parked(Conn &conn, H2Stream &stream, std::string &sink, bool complete);
    // #53: the body a parked run stopped for is whole. True = a run was
    // waiting on it and its round is ready now, so the stream must not be
    // served a second time.
    bool h2_body_ready(Conn &conn, uint32_t stream_id);
    bool h2_extended_connect(Conn &conn, const H2Connect &request_ask, std::string &sink);
    // A parked stream's request as a view: the target it named, and the
    // ReqView the caller owns for it to point into.
    struct Parked {
        std::string_view target;
        ReqView &view;
        // Where the re-match writes its captures. The view only points at
        // them, so they have to live in the caller's frame, beside the view.
        RouteSpans &spans;
    };
    const ReqView *h2_parked_view(Conn &conn, Parked bytes);
    // What one h2 access line is written from: the facts the stream carried,
    // and the :path they were read beside - which is still live only here.
    struct H2Logged {
        const flow::ReqFacts &facts;
        std::string_view target;
    };
    void h2_log(Conn &conn, const H2Logged &l);
    // `target` rides beside `req` because an error answer needs it even
    // when no route matched - a 404 names what was not found, and that is
    // exactly the case where there is no ReqView (#210).
    // RFC 9113 8.1: one stream's request, as much of it as answering needs.
    // Eight arguments travelled together - see #std-first.
    struct H2Request {
        uint32_t stream_id;
        const flow::ReqFacts &facts;
        const http::ReqValues *vals;
        const ReqView *req;
        std::string_view target;
        uint16_t route;
        bool head_only;
        // #54: the bytes every field of this request points into - the
        // dispatch's decode buffer, or a parked stream's own copy of it.
        // A run that can stop copies this range into its frame and rebases
        // the view onto the copy, so it still has a request after the
        // buffer is reused. Null for a caller that has no such range, and
        // then a run that stops answers from the head alone.
        const char *head_at = nullptr;
        size_t head_len = 0;
        // #53: is the whole body here? A stream served while its DATA is
        // still coming says no, and two things follow: the walk stops at the
        // first node that reads content, and the stream is not half closed -
        // more of the request is on its way. Every caller that serves a whole
        // request leaves this alone.
        bool complete = true;
        // The route's bundle, looked up once by whoever built this. Null
        // for kNoRoute. h2_serve and h2_produce read it instead of asking
        // bundles_ a second and a third time per request.
        const Bundle *bundle = nullptr;
    };
    // Whether a run on this bundle can stop: it declared compute or
    // watch, or a value round. Only such a run pays for a frame.
    static bool h2_can_stop(const Bundle *block);
    // #30: the walk, and the framing, are two functions - a run can stop
    // between them. One framer serves both paths.
    struct H2Produced;
    void h2_produce(Conn &conn, const H2Request &q, bool can_park, H2Produced &bytes);
    void h2_after_run(Conn &conn, const H2Request &q, H2Produced &bytes, uint16_t status);
    bool h2_answer(Conn &conn, const H2Request &q, std::string &sink);
    // RFC 9110 15.5.12: the 411 itself, and the stream that earns one -
    // content whose length the client did not declare.
    // #30: which of the two an h2 request takes - the straight answer, or
    // a run that may stop. The resource decides: only one that declared
    // `compute` or `watch` can stop, and only that one pays for a frame.
    // What h2_serve did with the request: answered it into the sink,
    // parked a run for it, or closed the connection.
    enum class H2Served : uint8_t { kAnswered, kParked, kClosed };
    H2Served h2_serve(Conn &conn, const H2Request &q, std::string &sink);
    // WHATWG HTML over RFC 9113: what an event stream needs to open on one
    // h2 stream. The request's own bytes, because sse_open runs the
    // resource's initialize and that reads `request`.
    struct H2SseAsk {
        uint32_t stream_id;
        uint16_t route;
        std::string_view target;
        RouteSpans *spans;
        const void *fields;
        size_t nfields;
        const http::ReqValues *vals;
    };
    bool h2_sse_begin(Conn &conn, const H2SseAsk &request_ask, std::string &sink);
    void h2_sse_second(Conn &conn, std::string &sink);
    // RFC 8441: a WebSocket on one h2 stream, opened by the extended
    // CONNECT. The same fields the event stream needs, plus what the
    // handshake reads.
    struct H2WsAsk {
        uint32_t stream_id;
        uint16_t route;
        std::string_view target;
        RouteSpans *spans;
        const void *fields;
        size_t nfields;
        const http::ReqValues *vals;
    };
    bool h2_ws_begin(Conn &conn, const H2WsAsk &request_ask, std::string &sink);
    bool h2_frame(Conn &conn, const H2Request &q, std::string &sink, H2Produced &bytes);
    void h2_flush_pending(Conn &conn, std::string &sink, Plan *plan);
    void h2_build_asset_blocks(AssetEntry &entry);
    void h2_build_asset_shared();
    // RFC 9113 6.1/6.9: one asset answer on one stream - the stream it goes
    // out on, the entry it comes from, the status it carries, whether the
    // request wants the body behind the head, and the half-open window of
    // the wire body this answer covers.
    struct H2Asset {
        uint32_t stream_id;
        const AssetEntry &entry;
        uint16_t status;
        bool head_only;
        size_t win_off;
        size_t win_end;
    };
    bool h2_asset_answer(Conn &conn, const H2Asset &answer, std::string &sink);

    struct AppSlot {
        const RouteTable *table = nullptr;
        uint16_t base = 0;
        uint16_t count = 0;
        const RouteTable *ws_table = nullptr;
        uint16_t ws_base = 0;
        const RouteTable *sse_table = nullptr;
        uint16_t sse_base = 0;
        // The listener serves TLS: request.base_uri says https.
        bool tls = false;
        // RFC 9110 15.5.14: conf.max_body, in octets.
        size_t max_body = kMaxBodyDefault;
    };

    time_t sec_ = 0;
    std::vector<AppSlot> apps_;
    std::vector<Bundle> bundles_;
    std::vector<const WsResource *> ws_res_;
    std::vector<const SseResource *> sse_res_;
    std::vector<Variants> store_;
    std::vector<Variants> store_prefix_;
    std::array<uint16_t, 600> index_{};
    ErrorPages err_pages_;
    // Not the operator's --assets: the pictures an error page names, under
    // their own reserved prefix, mounted whether or not anything else is.
    Assets *error_assets_ = nullptr;
    std::vector<H2Block> h2_store_;
    H2Block h2_asset405_;
    H2Block h2_asset406_;
    Assets *assets_ = nullptr;
    // Set only in the standalone tier; null means no docroot answers here.
    const MimeDb *mime_ = nullptr;
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
    const Bundle *b = nullptr;
    const std::array<uint16_t, 600> *idx = nullptr;
    uint16_t status = 0;
    bool have_body = false;
    bool dynamic = false;
    // What this run lent instead of copying, if anything: not yet owned by
    // a stream, so every path out of the framing still has to place or
    // free it.
    mrb_state *lent_mrb = nullptr;
    mrb_value lent_v = {};
    const char *lent = nullptr;
    size_t lent_len = 0;
    bool lent_have = false;
    // The scratch this answer was spelled into. The straight path hands in
    // the writer's own; a parked run hands in a pair of its own, because
    // the writer's would be written over by the next request.
    std::string *body = nullptr;
    std::string *rhdrs = nullptr;
};
} // namespace webmachine

#endif
