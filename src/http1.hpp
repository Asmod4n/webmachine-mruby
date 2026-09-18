// The translation units that frame requests read this; the others read
// webmachine.hpp alone, the contract between the tiers.
#ifndef WEBMACHINE_HTTP1_HPP
#define WEBMACHINE_HTTP1_HPP

#include "webmachine.hpp"

#include "h2_wire.hpp"

#include <optional>
#include <picohttpparser.h>
#include <slipstream_tmpfile.h>

namespace webmachine
{

struct AssetEntry;

// RFC 9110 6.4: a body of this size or more goes to a file, not memory.
// The number is one response window (kResponseFileWindow).
inline constexpr size_t kBodySpill = 256u * 1024;
// RFC 9113 5.1.2: the most body files one h2 connection may hold open.
inline constexpr size_t kH2SpillFilesMax = 16;
// RFC 9112 7.1: the framing budget of a chunked body, in two parts.
// The floor covers a chunk extension, a trailer section and the size lines.
// A chunk of one octet spends five framing octets, so a rate of five
// lets a body of one-octet chunks pass.
inline constexpr size_t kChunkFramingFloor = 64u * 1024u;
inline constexpr size_t kChunkFramingPerOctet = 5u;

// The most answered content one connection or one stream may hold for a
// peer that does not read it. At line rate one minute is gigabytes.
inline constexpr size_t kTunnelOutCap = 8u * 1024 * 1024;

// RFC 9110 6.4: a request body in a file. slipstream_tmpfile made the
// file, so it has no name. An fd of -1 means the body is in memory.
enum class SpillOpen : uint8_t { kOpen, kNoSlot, kNoFile };

struct BodySpill {
    int fd = -1;
    size_t written = 0;
    // Until a run takes the file, closing it drops a body that still arrives.
    bool bound = false;
    // The kernel writes from the reactor's own buffer, never from here: this
    // object dies with its connection or its stream.
    std::string pending;
    bool in_flight = false;
    size_t offset = 0;
    bool failed = false;
    bool ended = false;

    void close_file();
    // kNoSlot is load: h1 answers 503, h2 refuses the stream. kNoFile is a 500.
    SpillOpen open_file();
    // Nothing here writes: a blocking write(2) on this thread stalled every
    // other connection when the file was on a disk. The reactor arms the write.
    // A move steals the descriptor, so a moved H2Stream cannot close a file twice.
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
    bool take(const char *bytes, size_t count);
    // One write at a time: the file has one offset.
    bool owes_write() const;
    // A descriptor that still owes octets answers a short read.
    bool drained() const;
    // The octets move into the reactor's buffer, so the kernel never writes
    // from memory this object owns.
    void fly_into(std::string &out_value);
    void wrote(ssize_t resource, const std::string &out_value);
};

struct SseStream;
void sse_free(SseStream *sqe);
struct WsConn;
void ws_free(WsConn *conn);

struct MemWriter {
    std::string *mem;
    bool put(const char *bytes, size_t count) const;
};

struct FileWriter {
    BodySpill *spill;
    bool put(const char *bytes, size_t count) const;
};

// nm -S on the host build: a switch on this costs 87 bytes in feed_parse
// and saves nothing, so the feed still tests the four pointers.
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

// Only an asset comes back to kHead. An upgrade and an event stream end
// with the connection.
inline constexpr bool conn_move_ok(ConnMode from, ConnMode target_ring)
{
    if (from == target_ring)
        return true;
    switch (from) {
        case ConnMode::kHead:
            return true;
        case ConnMode::kAsset:
            return target_ring == ConnMode::kHead;
        case ConnMode::kWs:
            return false;
        case ConnMode::kSse:
            return false;
    }
    return false;
}

static_assert(conn_move_ok(ConnMode::kHead, ConnMode::kWs));
static_assert(conn_move_ok(ConnMode::kHead, ConnMode::kSse));
static_assert(conn_move_ok(ConnMode::kHead, ConnMode::kAsset));
static_assert(conn_move_ok(ConnMode::kAsset, ConnMode::kHead));
static_assert(!conn_move_ok(ConnMode::kWs, ConnMode::kHead));
static_assert(!conn_move_ok(ConnMode::kSse, ConnMode::kHead));
static_assert(!conn_move_ok(ConnMode::kWs, ConnMode::kSse));
static_assert(conn_move_ok(ConnMode::kAsset, ConnMode::kHead) &&
              !conn_move_ok(ConnMode::kWs, ConnMode::kHead));

// kFailed is 400, kTooLarge 413, kNoSlot 503, kFileFailed 500.
enum class BodyTake : uint8_t { kNone, kMore, kWhole, kFailed, kTooLarge, kNoSlot, kFileFailed };

// RFC 9113 8.3: offsets, not views. The blob grows while fields are copied
// into it, and the stream moves with its container.
struct H2FieldSpan {
    uint32_t name_at;
    uint32_t name_len;
    uint32_t value_at;
    uint32_t value_len;
};

struct H2Stream {
    uint32_t id = 0;
    // RFC 9113 6.9.1: signed, because a SETTINGS_INITIAL_WINDOW_SIZE change
    // can drive it negative.
    int64_t flow_window = kH2DefaultWindow;
    size_t content_received = 0;
    std::string request_content;
    // RFC 9110 6.4: one file per stream, because an h2 connection carries
    // many uploads at once.
    BodySpill spill;
    size_t content_length = 0;
    bool content_length_given = false;
    enum class Data : uint8_t { kMem, kFile, kDrop };
    Data data = Data::kDrop;
    size_t max_body = 0;
    // RFC 9113 8.3: hdrbuf is reused by the next dispatch, so a parked
    // request's fields are copied here.
    std::string field_blob;
    std::vector<H2FieldSpan> field_spans;
    flow::ReqFacts facts;
    const AssetEntry *parked_asset = nullptr;
    uint16_t parked_status = 0;
    // RFC 9113 5.1: the entry stays until the run answers, so a RST_STREAM
    // or a WINDOW_UPDATE for it finds it.
    bool parked = false;
    size_t parked_first = 0;
    size_t parked_end = 0;
    struct Content {
        enum class Src : uint8_t { kNone, kAsset, kLent, kOwned };
        // kAsset: RFC 1952 framing makes one range up to three iovecs, so the
        // entry travels and not a pointer.
        const AssetEntry *asset = nullptr;
        const char *lent = nullptr; // kLent: the handler's frozen String
        std::string owned;          // kOwned: what flow control could not frame
        size_t sent = 0;
        size_t length = 0;
        // Non-null exactly while an unroot is owed. H2State::content_retire is
        // the one place that clears it, so no value is unrooted twice.
        mrb_state *mrb = nullptr;
        mrb_value value = {};
        Src src = Src::kNone;
        // RFC 9113 6.9.1: owed octets keep the stream and the lend alive.
        bool owes() const
        {
            return src != Src::kNone && sent < length;
        }
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
        void take_lent(mrb_state *vm, mrb_value lent_value, const char *bytes, size_t count)
        {
            src = Src::kLent;
            lent = bytes;
            sent = 0;
            length = count;
            mrb = vm;
            value = lent_value;
        }
        void take_owned(const char *bytes, size_t count)
        {
            src = Src::kOwned;
            owned.assign(bytes, count);
            sent = 0;
            length = count;
        }
        // What has left is dropped from the front, so a stream that runs for
        // hours holds only what the window has not taken.
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
    uint16_t route = 0;
    std::string request_target;
    bool head_method = false;
    bool end_headers = false;
    bool half_closed_remote = false;
    // RFC 8441: the stream's DATA frames hold RFC 6455 frames.
    WsConn *ws = nullptr;
    SseStream *sse = nullptr;
    // RFC 9113 6.1: an event stream sends its next tick later, so the last
    // DATA frame of a tick must not carry END_STREAM.
    bool streaming = false;
};

inline constexpr size_t kPhrHeaderSlots = 64;
static_assert(kPhrHeaderSlots <= 255, "http::NamedFieldIndex::at holds a field's place in one byte");
inline constexpr size_t kH2FieldSlots = kPhrHeaderSlots + 8;

struct H2DecodedField {
    std::string_view name;
    std::string_view value;
    uint8_t known;
};

struct H2State {
    struct lshpack_enc enc;
    struct lshpack_dec dec;

    int64_t flow_window = kH2DefaultWindow;
    int64_t peer_initial_window = kH2DefaultWindow;
    uint32_t peer_max_frame = kH2MaxFrameSize;
    uint32_t last_stream = 0;
    uint32_t highest_opened = 0;
    size_t flush_cursor = 0;
    bool goaway_sent = false;
    bool goaway_recv = false;
    // RFC 9113 8.1.1: streams lost to a body that did not match its
    // Content-Length. One costs one stream; a run of them ends the connection.
    uint32_t lies = 0;

    // RFC 9113 8.1: a reset frees the stream slot at once, so
    // MAX_CONCURRENT_STREAMS bounds nothing here.
    uint32_t resets = 0;
    int64_t resets_window_began = 0;

    std::string frag;
    uint32_t frag_stream = 0;
    uint8_t frag_flags = 0;
    bool frag_active = false;

    std::string hdrbuf;
    // Built once with the connection, so no request constructs kH2FieldSlots
    // empty views.
    std::array<H2DecodedField, kH2FieldSlots> decoded_fields;
    size_t decoded_count = 0;

    std::vector<H2Stream> streams;

    // RFC 7541 2.3.3 / 4.1: every insert shifts the index of every older
    // entry. A cached head is valid only while nothing was inserted since it
    // was built.
    uint64_t enc_ins = 0;

    struct {
        std::string bytes;
        size_t head_len = 0;
        uint64_t enc_ins = 0;
        // RFC 7541 6.2.1: a dynamic-table entry must reach the peer once before
        // anything may reference it, so the response that builds it carries this form.
        std::string prime;
        bool primed = false;
        bool has_data = false;
        uint16_t status = 0;
        uint16_t route = 0xffff;
        time_t sec = 0;
    } head_cache;

    // The writer still points at this body until the round drains, so it
    // waits for Http1::Conn::zc_release.
    struct Lend {
        mrb_state *mrb;
        mrb_value v;
    };
    std::vector<Lend> retired;

    // ls-hpack: lshpack_enc_init can fail. A constructor cannot refuse, so
    // it records and h2_begin refuses.
    bool hpack_ready = false;
    H2State();
    ~H2State();
    H2State(const H2State &) = delete;
    H2State &operator=(const H2State &) = delete;

    H2Stream *find(uint32_t stream_id)
    {
        for (H2Stream &st : streams)
            if (st.id == stream_id)
                return &st;
        return nullptr;
    }
    H2Stream &open(uint32_t stream_id);
    // Clears `mrb`, so a second call is a no-op and no value is unrooted twice.
    void content_retire(H2Stream &sqe);
    // Called where a whole round has drained, so nothing the kernel holds
    // still points into these Strings.
    void content_drain();
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

// RFC 7692 4.2/5.1: declining is never an error.
struct Negotiated {
    Params &params;
    std::string &echo;
};

bool negotiate(std::string_view value, Negotiated out_value);
// RFC 7692 7: the codec lives in wsconn.cpp. Params and negotiate stay
// here because the h1 upgrade path negotiates before a WsConn exists.
class Codec;
} // namespace wsdeflate
} // namespace webmachine

namespace webmachine
{
inline constexpr size_t kMaxWsMessageDefault = 64u * 1024;

struct WsConn;

bool ws_wants_deflate(const WsResource *round);

// RFC 6455 4.2.2: status 0 = admitted.
struct WsAdmit {
    std::string &proto;
    uint16_t &status;
};
WsConn *ws_admit(const WsResource *round, Logger *elog, WsAdmit out_value);

void ws_open(WsConn *conn, const wsdeflate::Params &deflate);

bool ws_feed(WsConn *conn, std::string_view data, std::string &sink);

// RFC 6455 7.1.1: a Close frame goes first. True = this call wrote one.
bool ws_going_away(WsConn *conn, std::string &sink);

void ws_free(WsConn *conn);
} // namespace webmachine

namespace webmachine
{
struct SseStream;

SseStream *sse_open(const SseResource *round, Logger *log, uint16_t &code);

bool sse_second(SseStream *sqe, int64_t now_s, std::string &sink);
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

// RFC 6455 5.2: what the header bytes decide on their own. Pure, so the
// Autobahn cases test a table and not a socket.
struct Head {
    enum class Err : uint8_t { kNone, kProtocol, kTooBig };
    Err err = Err::kNone;
    uint8_t opcode = 0;          // RFC 6455 5.2: Opcode
    uint64_t payload_length = 0; // RFC 6455 5.2: Payload length
    uint8_t masking_key_at = 0;
    bool fin = false;     // RFC 6455 5.2: FIN
    bool rsv1 = false;    // RFC 6455 5.2: RSV1, negotiated by RFC 7692
    bool control = false; // RFC 6455 5.5: opcode has the high bit
};

// RFC 6455 5.2: read_head reads every header octet unconditionally, so
// this must be true before read_head is called.
uint8_t header_need(const unsigned char *headers, uint8_t have);

// RFC 6455 5.3: transformed-octet-i = original-octet-i XOR
// masking-key-octet-(i MOD 4). `at` keeps the key aligned across recvs.
struct Mask {
    const unsigned char *key;
    size_t at;
};

void unmask_copy(char *dst, std::string_view src, Mask method);

Head read_head(const unsigned char *headers, bool have_codec);

struct Message {
    uint8_t op;
    bool deflated;
    uint64_t len;
    uint64_t max;
};

// RFC 6455 5.4 and 7.4.1.
Head::Err admit(const Head &headers, const Message &msg);

struct Frame {
    uint8_t opcode;
    bool fin;
    bool rsv1;
    size_t payload_len;
};
size_t header_build(Frame field, char head[10]);

// RFC 6455 5.5.1: 1005 = the peer named no code.
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
bool sse_tick(SseStream *sqe, int64_t now_s, std::string &body);
void sse_free(SseStream *sqe);

struct H2State;
void h2_free(H2State *h2_state);

class Assets;
struct AssetEntry;

// Reserved, so an operator's own tree can never collide with it.
inline constexpr char kErrorAssetsPrefix[] = "/error_assets/";
inline constexpr size_t kErrorAssetsPrefixLen = sizeof(kErrorAssetsPrefix) - 1;
inline constexpr size_t kCompressFloor = 1280;
inline constexpr size_t kDeliverChunk = 64u * 1024;

// response.file reads one window at a time, so per-connection memory is
// O(window) and not O(file). kDone: the last lend is on the wire, so the
// mapping goes back on the drained round after it.
enum class FileStage : uint8_t { kNone, kNamed, kRing, kDeliver, kDone };

struct FileStep {
    enum class Src : uint8_t { kNone, kWindow, kMapping };
    Src src = Src::kNone;
    size_t start = 0;      // RFC 9110 6.4
    size_t give = 0;
    size_t sent_after = 0; // RFC 9110 8.6: content_sent once it lands
    FileStage next = FileStage::kNone;
    bool head = false;        // RFC 9112 2.1: rides the first round only
    bool release_map = false; // munmap: off the wire, may go back
    bool log = false;
    bool clear = false;
    bool persist = true;      // RFC 9112 9.3
};

// 16 kbit/s is half the slowest throttle a mobile network applies once an
// allowance is spent (Vodafone and O2: 32 kbit/s). Half, because the send
// deadline refreshes per completed send.
inline constexpr size_t kSlowClientRate = 2000;
// One sendmsg moves at most MAX_RW_COUNT (INT_MAX rounded down to a
// page). A body offered past that comes back short, which reads like a
// dead peer. The floor holds a frame and its head under a short send_timeout.
inline constexpr size_t kFileSendChunkMin = 4096;
inline constexpr size_t kFileSendChunkMax = 64u * 1024 * 1024;

// At the default 60 s this is 120,000 bytes. The same number bounds the
// kernel call and decides who is dropped mid-download.
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
    // Ordered by alignment: flags among the pointers cost 34 bytes of
    // padding in 176.
    struct Plan;

    // Only a resource that declared a promise or a watch runs through a
    // frame. `view`, `method`, `path` and every field in ReqValues point into
    // a provided buffer that on_recv gives back before anything resumes, so
    // the frame holds a copy.
    struct Run {
        struct promise_type;
        using handle = std::coroutine_handle<promise_type>;

        struct promise_type {
            uint16_t status = 0;
            bool finished = false;
            // The plan of the round that started the run is gone, and the sink may
            // have swapped while the run was stopped. The resumer sets these before
            // resume().
            std::string *sink = nullptr;
            struct Plan *plan = nullptr;
            bool persist = true;
            int park = -1;

            Run get_return_object()
            {
                return Run{handle::from_promise(*this)};
            }
            // Eager: a run that never stops reaches its answer inside the call that
            // started it.
            std::suspend_never initial_suspend() noexcept
            {
                return {};
            }
            // A self-destroying coroutine would take the answer with it.
            std::suspend_always final_suspend() noexcept
            {
                return {};
            }
            void return_value(uint16_t sqe)
            {
                status = sqe;
                finished = true;
            }
            // The run frames above catch the throw. This frame stays suspended at
            // its final point, where the caller destroys it.
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
        // The handle is the parked run's name; there is no slot table.
        handle release()
        {
            const handle h = co;
            co = {};
            return h;
        }

        handle co{};
    };

    // The sink and the plan belong to the round that resumes the run, not
    // the one that started it, so the promise is the only way to reach them.
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

    // A coroutine cannot name its own promise. await_suspend returning
    // false reads the frame without leaving it.
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
        std::string carry;
        size_t content_skip = 0;
        // RFC 9110 6.4: the bytes collect in `carry` behind the head, so the
        // hand-off is zero-copy.
        size_t content_need = 0;
        // RFC 9110 6.4: it cannot stay in `carry`: a pipelined request behind
        // it wants that buffer.
        std::string body_hold;
        bool run_wants_body = false;
        // RFC 9110 6.4: one file per connection, because h1 answers one request
        // at a time.
        BodySpill spill;
        enum class Body : uint8_t { kNone, kMem, kFile, kChunkMem, kChunkFile };
        Body body_to = Body::kNone;
        // RFC 9112 7.1: picohttpparser's state. Zero filled, with consume_trailer
        // set, so the decoder reads and drops the trailer section.
        struct phr_chunked_decoder chunk = {};
        // The decoder rewrites what it is given, and the receive buffer holds a
        // pipelined request behind the body.
        std::string chunk_buf;
        // RFC 9110 15.5.14: a chunked body has no declared length, so the limit
        // is held against this count.
        size_t body_count = 0;
        size_t body_limit = 0;
        // RFC 9112 7.1: framing is not the body, so body_limit never sees it, and
        // a client that sends framing and no content would send it forever.
        size_t chunk_framing = 0;
        // RFC 9112 7.1.1: picohttpparser accepts chunk-size lines the grammar
        // does not allow, so this walk holds the same octets to the text first.
        enum class ChunkScan : uint8_t { kSize, kData, kAfterData, kDone };
        ChunkScan chunk_scan = ChunkScan::kSize;
        size_t chunk_need = 0;
        uint8_t chunk_after = 0;
        std::string chunk_line;
        // RFC 9110 8.3: the check runs after the head is gone from the buffer.
        // Empty = the route asked for no check.
        std::string sniff_type;
        // Kept apart from the body: the body may go to a file, and the check
        // must not read it back.
        std::string sniff_head;
        bool sniff_done = false;
        ConnMode mode = ConnMode::kHead;
        void become(ConnMode target_ring)
        {
            if (kDebugBuild && !conn_move_ok(mode, target_ring)) {
                std::fprintf(stderr,
                             "webmachine: a connection went from %s to %s, which it cannot\n",
                             conn_mode_name(mode), conn_mode_name(target_ring));
                std::abort();
            }
            mode = target_ring;
        }
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

        // Only a fact stored twice needs a check that the two agree.
        const char *invariant_broken() const
        {
            // A chunked body owes octets until its own machine says the last chunk
            // came, so content_need says nothing about it.
            const bool chunked = body_to == Body::kChunkMem || body_to == Body::kChunkFile;
            if (!chunked && (content_need != 0) != (body_to != Body::kNone)) {
                return "octets are owed and no destination is named, or the other way round";
            }
            if (chunked && content_need != 0)
                return "a chunked body counts octets it did not declare";
            if (body_to == Body::kFile && spill.fd < 0)
                return "a body goes to a file that is not open";
            if (body_to == Body::kChunkFile && spill.fd < 0) {
                return "a chunked body goes to a file that is not open";
            }
            // The upgrade is the end of the request that carried it.
            if ((mode == ConnMode::kWs || mode == ConnMode::kSse) &&
                (content_need != 0 || content_skip != 0)) {
                return "an upgraded connection still owes octets of a request body";
            }
            return nullptr;
        }
        // A span into the wire body of an asset (Assets::wire_iov), not into the
        // file: a gzip member's octets are not the stored ones.
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
        // "zc" is the [tune] knob's word, zero_copy_threshold: lent instead of
        // copied, rooted from the handler's return until the round drains.
        mrb_state *zc_mrb = nullptr;
        mrb_value zc_value = {};
        Run parked;
        // RFC 9112 9.3.2 lets h1 stop only one run; h2 stops one per stream.
        struct H2Parked {
            uint32_t stream_id = 0;
            Run run;
        };
        std::vector<H2Parked> h2_parked;

        static constexpr int kJobSlots = kValueJobs;
        // RFC 9112 9.3.2: responses go out in the order the requests came, so
        // nothing else speaks for the connection while a run is stopped.
        bool run_parked() const
        {
            return static_cast<bool>(parked.co) && !parked.done();
        }

        // A struct of its own because an h2 connection holds one per stopped
        // stream.
        struct Round {
            // Rooted while it waits: nothing on the VM's stack names it. The channel
            // is as wide as a value round; slot 0 is the single job's and a watcher's.
            std::array<mrb_value, kJobSlots> answer_value{};
            // The resume is the one point where a fresh sink and plan exist to
            // write into.
            bool answer_ready = false;
            // The frame crosses the work at the stop, the last moment the reactor's
            // VM and the run's state are both in hand.
            struct Job {
                unsigned code = 0;
                std::string bytes;
                double deadline = 0.0;
                bool waiting = false;
            };
            std::array<Job, kJobSlots> job{};
            // kJobNode for a node's own callback. A watcher has no Job.
            std::array<uint8_t, kJobSlots> job_what{};
            uint8_t jobs_owed = 0;
            // Nothing was handed to a worker or the ring; the connection makes the
            // round ready when the last octet lands.
            bool wants_body = false;
            uint8_t jobs_answered = 0;
            // It outlives the crossing, because the answer comes long after.
            const Resource *job_res = nullptr;
            std::array<int, kValueJobs> w_slot{{-1, -1, -1, -1}};
            enum class ComputeEnd : uint8_t {
                kAnswered,     // the worker answered, and the walk goes on
                kPoolFull,     // no slot: load, and load passes - 429 with a
                               // Retry-After of a few seconds
                kOverDeadline, // the worker ended it at its max_runtime. Not
                               // load: a second attempt costs the same, so
                               // 500 and no Retry-After
                kNotCrossed,   // mruby could not dump the block, or CBOR could
                               // not carry the arguments - 500, and the error
                               // log says which
                kRaised,       // the worker raised. The registry holds what
                               // dies, a database or a connection, so 503 with
                               // a Retry-After of a minute
            };
            ComputeEnd compute_end = ComputeEnd::kAnswered;
        };
        // The Round lives in the coroutine frame. This table is only what the
        // reactor needs: a completion carries a number, not an address. Four bits
        // of the tag name the park slot and four name the job.
        static constexpr int kParkSlots = 16;
        Round *park[kParkSlots] = {};
        // Sixteen slots is sixteen bits: a free slot is the first zero of
        // `taken`, the next round to arm the first one of `owes`, both through ctz.
        uint16_t park_taken = 0;
        uint16_t park_owes = 0;
        // A round refused halfway leaves earlier jobs in flight, and the next run
        // takes the same slot. An answer that names a taking that ended is dropped.
        uint8_t park_gen[kParkSlots] = {};
        void park_wants_arming(int slot)
        {
            if (slot < 0 || slot >= kParkSlots)
                return;
            park_owes |= static_cast<uint16_t>(1u << slot);
        }

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
        // An mruby Hash, not a C++ map: a watcher nobody holds is collected with
        // the source and block it keeps alive. One gc_register roots them all.
        // A late completion for a gone connection is discarded by the generation
        // guard `!c.live || c.gen != gen`, so nothing here counts anything.
        mrb_state *w_mrb = nullptr;
        mrb_value w_hash = {};
        // Http1 has no ring, so the reactor collects what is pending here.
        std::vector<int> w_pending;
        uint8_t listener = 0;
        uint8_t peer_len = 0;
        bool fresh = true;
        bool packetized = false;
        bool zc_lent = false;
        bool zc_split = false;
        // Lazy: most connections never call response.file=, and the strings
        // would cost the accept, recv and send path. Allocated once and kept
        // for the life of the connection; `reset()` and `~Conn()` delete it.
        // The kernel's fields are named for the arguments they become. The
        // access line's are copies: the request is gone when the ring answers.
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
            size_t buf_filled = 0;
            // RFC 9110 8.6: the two unequal is what keeps a file alive across rounds.
            size_t content_length = 0;
            size_t content_sent = 0;
            // Survives file_clear(): the SQE still points into it. It goes back on
            // the kDone round, the round after the last lend.
            const char *map_addr = nullptr; // munmap(addr, length)
            size_t map_length = 0;
            bool map_wanted = false;
            int64_t if_modified_since = 0; // RFC 9110 13.1.3
            uint16_t status_code = 0;      // RFC 9110 15
            uint8_t log_flags = 0;         // LogRec::flags, see kLogH2
            FileStage stage = FileStage::kNone;
            bool persist = true;    // RFC 9112 9.3
            bool head_only = false; // RFC 9110 9.3.2
            bool if_modified_since_valid = false;
            int err_media = 0;
            int minor = 1; // RFC 9112 2.3: second DIGIT
        };
        FileXfer *file = nullptr;
        void file_clear()
        {
            if (file == nullptr)
                return;
            file->stage = FileStage::kNone;
            file->buf_filled = 0;
            // A stale content_length would be read as the next request's.
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
        // Unconditional at connection end: a mapping nobody borrowed still has
        // to go.
        void map_release()
        {
            if (file == nullptr || file->map_addr == nullptr)
                return;
            if (::munmap(const_cast<char *>(file->map_addr), file->map_length) != 0)
                die_errno("munmap a lent file", errno);
            file->map_addr = nullptr;
            file->map_length = 0;
        }
        // Never conditional on the round having succeeded.
        void zc_release()
        {
            // The mapping goes back from file_step(), not here. h2's last bytes are
            // still in flight where a stream ends, and this is the point that knows
            // they are not.
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
        // The slot is the key here and the field the completions carry back.
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

        // Emptied here, so the later sweep frees nothing twice.
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

        // Unrooting the hash makes the watchers collectable; each CDATA
        // destructor takes its descriptor out of the ring.
        void watchers_release()
        {
            w_pending.clear();
            if (w_mrb == nullptr)
                return;
            mrb_gc_unregister(w_mrb, w_hash);
            w_mrb = nullptr;
            w_hash = mrb_nil_value();
        }
        // The ring may go before the VM collects the watchers, so each is
        // emptied first and its destructor has no ring to cancel on.
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
        void reset(uint8_t listener_index, bool pkt)
        {
            zc_release();
            watchers_release();
            // The frame holds the roots and the round; destroying it gives them back
            // (see ParkedRoots in run_parkable).
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
        // Run is move-only. A slot is built where it lives and never moves (see
        // conns_). A defaulted move would copy ws/sse/h2/file and the GC
        // registration and leave the source owning them too.
        Conn() = default;
        Conn(const Conn &) = delete;
        Conn &operator=(const Conn &) = delete;

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
        // RFC 9110 15.5.14: conf.max_body.
        size_t max_body = kMaxBodyDefault;
    };

    Http1(const AppInput *apps, size_t napps, Assets *assets = nullptr);
    Http1(const RouteTable &table, const Resource *const *resources, size_t nroutes,
          Assets *assets = nullptr);

    // The h1 model is bytes in, bytes out, so this layer is handed a VM
    // rather than owning one.
    void open_error_assets(mrb_state *mrb, Assets *error_assets);

    // The old pack is not freed here: a response on the wire may still lend
    // its bytes, and the caller owns that decision.
    void swap_assets(Assets *assets);

    // `listings`: a target that names a directory belongs to the listing
    // application, so this tier answers no for one.
    void serve_docroot(const MimeDb *mime, bool listings);

    void clock_tick();

    bool pending(const Conn &conn) const;

    bool tunneled(const Conn &conn) const;

    // RFC 6455 7.1.1: a WebSocket says goodbye with a Close frame. True =
    // something was written.
    bool going_away(Conn &conn, std::string &sink);

    bool timed(const Conn &conn) const;

    // This becomes a struct msghdr, so it carries that struct's names. `off`
    // is not ABI: a sink segment cannot know its address until the sink has
    // stopped growing.
    struct Plan {
        struct Seg {
            const char *iov_base;
            size_t off; // not ABI: where in the sink, when iov_base is null
            size_t iov_len;
        };
        static constexpr unsigned kSegs = 1023;
        Seg iov[kSegs];
        unsigned iovlen = 0;
        size_t byte_total = 0;
        size_t byte_cap = 0;
    };

    // `plan` is null where this caller is not planning a send.
    struct Sink {
        std::string &bytes;
        Plan *plan;
    };
    bool connection_feed(Conn &conn, std::string_view data, Sink out_value);

    bool spell_next_round(Conn &conn, std::string &sink, Plan &plan);

    // The bytes come back into the reactor's VM here, the only thread that
    // may build a value in it. A worker that raised is nil.
    static void compute_task_answered(Conn &conn, int park, int job, const ComputeAnswer &answered);
    static void round_answered(Conn::Round &round, int job, mrb_value value);
    static void compute_task_refused(Conn &conn, int park);
    // Status 0 = the worker answered. Retry-After holds a whole header line,
    // a constant, so a refusal costs no formatting and no allocation.
    struct ComputeRefusal {
        uint16_t status = 0;
        std::string_view retry_after;
    };
    static ComputeRefusal compute_task_refusal(Conn::Round &round);
    // After the crossing nothing of the VM is named, which lets a worker
    // touch the result. A raise here is the application's, not the run's, so
    // compute_task_cross is the half that raises under its own frame.
    bool compute_task_hand_over(Conn &conn, Conn::Round &round, int park, const Resource &resource);
    bool compute_task_cross(Conn &conn, Conn::Round &round, int park, const Resource &resource);
    // False when the connection can hold no more; the run is told the way a
    // full pool tells it.
    static bool watch_hand_over(Conn &conn, Conn::Round &round, int park, const Resource &resource);
    enum class WatchStep : uint8_t {
        kWait,  // the block wants the same thing again
        kRearm, // the block asked for other events
        kDone,  // the block called abort; `answer_value` is its last word
    };
    // The return value never means "keep waiting": a block may answer nil
    // and mean it.
    static WatchStep watcher_event(Conn &conn, int slot, unsigned revents);
    static WatchStep watcher_deadline(Conn &conn, int slot);
    static unsigned watcher_mask(Conn &conn, int slot);
    static int watcher_descriptor(Conn &conn, int slot);
    static void watcher_is_armed(Conn &conn, int slot, struct io_uring *ring, uint64_t poll_tag);
    static void watcher_is_unarmed(Conn &conn, int slot);
    static uint64_t watcher_poll_tag(Conn &conn, int slot);
    static void watchers_drop_slot(Conn &conn, int slot);
    static bool watch_take(Conn &conn, int *slot);
    static void watch_run_is(Conn &conn, Conn::Round &round, Resource::RunState *run);
    static size_t watchers_over_deadline(Conn &conn, int64_t now, int *slots, size_t max);
    static int64_t watchers_soonest_deadline(Conn &conn);
    static void watcher_armed_at(Conn &conn, int slot, int64_t index);
    static double watcher_quiet_seconds(Conn &conn, int slot);
    static bool compute_task_take(Conn &conn, int park, int job, unsigned *code, std::string &bytes,
                                  double *deadline);
    // Opening a file is disk work, so it never happens inside the run. Any
    // refusal lands as the same 404 file_reject spells.
    const char *file_take(Conn &conn);
    // file_take lives in another translation unit, and the call for an answer
    // that is almost always no measured 0.38% of a whole h1 run.
    static bool file_waiting(const Conn &conn);
    // Measured at 0.45% before this existed.
    static bool compute_task_waiting(const Conn &conn);
    static uint8_t park_generation(const Conn &conn, int park);
    static bool park_take_pending(Conn &conn, int *park);
    // RFC 9110 6.4: one write flies at a time, because the answer names a
    // connection and not a stream.
    static BodySpill *spill_waiting(Conn &conn);
    static BodySpill *spill_waiting_h2(Conn &conn);
    void spill_wrote(Conn &conn, ssize_t resource, const std::string &out_value);
    void file_reject(Conn &conn);
    // RFC 9110 15.4.2.
    bool file_redirect_to_directory(Conn &conn);
    void file_error(Conn &conn, const char *why);
    bool file_stat(Conn &conn, const struct statx &stx, size_t *want);
    char *file_buffer(Conn &conn, size_t count);
    void file_ready_now(Conn &conn, size_t count);
    void file_mapped(Conn &conn, const char *bytes, size_t count);
    // RFC 9110 5.6.2: the octets a token may carry.
    static bool chunk_tchar(char letter);

    static bool chunk_hex(char letter);

    // RFC 9112 7.1.1:
    //   chunk-size = 1*HEXDIG
    //   chunk-ext  = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
    // BWS stands only around the semicolon and the equals, so whitespace
    // anywhere else is refused.
    static bool chunk_size_line_ok(const char *bytes, size_t count);

    // RFC 9112 7.1.1: picohttpparser accepts `2 erfrferferf`, `2;`, `a ` and a
    // bare CR inside the line, so this holds the octets to the grammar first.
    static bool chunk_lines_ok(Conn &conn, const char *data,
                                                         size_t length);

    template <class W>
    static BodyTake take_chunked(Conn &conn, W window, const char *&data,
                                                           size_t &len)
    {
        if (len == 0)
            return BodyTake::kMore;
        // RFC 9112 7.1.1: the grammar first. A chunk reader that takes sizes
        // outside the grammar is where request smuggling is found.
        if (mrb_unlikely(!chunk_lines_ok(conn, data, len)))
            return BodyTake::kFailed;

        conn.chunk_buf.assign(data, len);
        size_t decoded = conn.chunk_buf.size();
        const ssize_t rest = phr_decode_chunked(&conn.chunk, conn.chunk_buf.data(), &decoded);
        if (mrb_unlikely(rest == -1))
            return BodyTake::kFailed;
        if (mrb_unlikely(conn.body_count + decoded > conn.body_limit))
            return BodyTake::kTooLarge;
        if (mrb_unlikely(decoded != 0 && !window.put(conn.chunk_buf.data(), decoded))) {
            return BodyTake::kFileFailed;
        }
        conn.body_count += decoded;
        // What the decoder did not read is a pipelined request.
        const size_t used = rest < 0 ? len : len - static_cast<size_t>(rest);
        // RFC 9112 7.1: the budget is kChunkFramingFloor plus
        // kChunkFramingPerOctet for every content octet.
        conn.chunk_framing += used - decoded;
        if (mrb_unlikely(conn.chunk_framing >
                         kChunkFramingFloor + conn.body_count * kChunkFramingPerOctet)) {
            return BodyTake::kFailed;
        }
        data += used;
        len -= used;
        // Once per body: memory goes to the file, and every octet after is a
        // file write.
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
        const size_t take = std::min(length, conn.content_need);
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

    // RFC 9110 6.4: closed here and not at the next accept into this slot,
    // or a spilled body keeps its descriptor open until then.
    static void drop_body(Conn &conn);

    static bool file_answerable(const Conn &conn);
    // The octets came in on the receive that fed the parser, so no completion
    // would ever come back to collect this answer.
    static bool run_resumable(const Conn &conn);
    // 0 = do not map; otherwise the exact length to map.
    static size_t file_map_len(const Conn &conn);
    // One value, decided once, so the writer and the access line cannot
    // disagree.
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
        size_t body_len = 0;
        bool answered = false;
    };
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

    struct H2SendStep {
        size_t start = 0;
        size_t give = 0;
        size_t total = 0;  // the body's length, so END_STREAM is a comparison
        bool ends = false; // give reaches the last byte
    };
    struct stream {
        int64_t conn_window;
        size_t chunk;
    };
    static H2SendStep h2_send_step(const H2Stream &sqe, stream room);

    //   status_code    RFC 9110 15
    //   first_byte_pos RFC 9110 14.1.2
    //   content_length RFC 9110 8.6: the span sent
    //   sends_content  RFC 9110 6.4
    struct AssetStep {
        enum class HeadKind : uint8_t { kRefusal, kNormal, kRange, kUnsatisfiable };
        HeadKind head = HeadKind::kNormal;
        uint16_t status_code = 200;
        size_t first_byte_pos = 0;
        size_t content_length = 0;
        bool sends_content = false;
    };
    // RFC 9110 14.1/14.2: a range is honoured only on a GET that would have
    // been a 200, and only when If-Range still matches.
    struct RangeAsk {
        uint16_t verdict;
        bool head_only;
        flow::Method method;
        const http::ReqValues &vals;
    };
    static AssetStep asset_step(const AssetEntry &entry, const RangeAsk &request_ask);

    // Defined here: `spell_next_round` lives in another translation unit and
    // this build has no LTO, so out of line it is a 48-byte return through
    // memory (SysV returns anything past 16 bytes that way).
    static FileStep file_step(const Conn::FileXfer &one, size_t chunk);
    void file_apply(Conn &conn, const FileStep &step);
    // The stage keeps the access line from being written twice.
    void file_log(Conn &conn);
    void file_abandon(Conn &conn);
    // Or a slot that once served a big file holds those bytes for the
    // process's life.
    static void file_release(Conn &conn);

    Logger *access_log();
    void enable_access_log();
    Logger *error_log();
    void enable_error_log();
    // [tune] zero_copy_threshold. Called once, before the first accept.
    void set_zero_copy_threshold(size_t count);

    // [tune] file_map_threshold. 0 = never map.
    void set_file_map_threshold(size_t count);
    // The Ring owns the send clock.
    void set_send_timeout(int secs);

  private:
    struct AppSlot;

    // WHATWG HTML: every member is a view or a reference into bytes the
    // caller owns for the length of the call.
    struct SseBegin {
        const AppSlot &slot;
        int route;
        std::string_view method;
        std::string_view path;
        const RouteSpans &spans;
        const void *hdrs; // struct phr_header[]
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
        const void *hdrs; // struct phr_header[]
        size_t nhdr;
        const http::ReqValues &vals;
        std::string_view rest;
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

    // Both outlive the framing: a body the window cannot finish is copied
    // onto the stream from here.
    struct H2ErrorPage {
        H2Block block;
        std::string rendered;
    };

    struct H2Answer {
        const char *body = nullptr;
        size_t blen = 0;
        const H2Block *blk = nullptr;
    };

    struct Bundle;

    struct H2ErrorAsk {
        uint16_t status;
        const ErrorPages::Fields &fields;
        const http::ReqValues *vals;
        const Bundle *bundle;
    };

    struct Bundle {
        flow::KonstSet konst;
        // RFC 9110 12.5.1: the media type without the charset parameter, present
        // even for the default route, which has no Resource.
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
    // RFC 9112 9.3: the Date bytes are a placeholder at boot.
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
    // RFC 9112: a head that stops before Content-Length.
    struct OpenPrefix {
        const char *status_line;
        const std::string &extra;
        const char *enc;
        const char *conn = "";
    };
    static void build_open_prefixes(Variants &value, OpenPrefix bytes);
    static void build_open_prefix(Resp &round, OpenPrefix bytes);
    // RFC 9113 6.2.
    struct CachedHead {
        const H2Block &block;
        std::span<const unsigned char> fields;
        std::span<const unsigned char> date;
    };
    static void cache_headers(std::string &out_value, const CachedHead &head);
    struct SseLine {
        std::string_view method;
        std::string_view path;
        const http::ReqValues &vals;
        uint16_t status;
        uint8_t lflags;
    };
    static void log_sse(Logger &logger, const Conn &conn, const SseLine &line);
    struct StatusText {
        const char *extra;
        const char *body;
    };
    void build_status(uint16_t status, StatusText text);
    void status_line_is_stocked(bool have[600], uint16_t sqe);
    void build_bundle(Bundle &block, const Resource *resource);
    static void patch_date(Variants &value, const char *core);
    // RFC 9112: a HEAD request takes the same head and none of the bytes.
    struct Assembled {
        const Resp &prefix;
        std::string_view body;
        bool head_only;
        // RFC 9111: a prebuilt prefix is shared by every target that reaches
        // this route, and only the target says whether the directory rule applies.
        std::string_view extra = {};
    };
    static void answer_assemble(std::string &sink, const Assembled &answer);
    bool feed_parse(Conn &conn, std::string_view data, Sink out_value);
    // The cold branches of feed_parse, out of line.
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
    struct Lending {
        std::string_view body;
        Plan &plan;
    };
    static void body_lend(Conn &conn, std::string &sink, Lending lend);
    // RFC 9110 12.5.3/12.5.5: gzip is on the table only when the peer accepts
    // it and this connection is packetized.
    struct DynamicBody {
        const Resp &prefix_id;
        const Resp &prefix_gz;
        // Handed in, never read off a member: a parked run writes into its own
        // string, and the writer's own already carries the next request.
        const std::string &body;
        bool may_gzip;
        bool head_only;
        // See Assembled::extra.
        std::string_view extra = {};
    };
    void assemble_dynamic(const DynamicBody &dynamic_body, std::string &sink);
    // RFC 9112 9.3.
    const Variants &variants(uint16_t status) const;
    const Variants &prefixes(uint16_t status) const;
    // RFC 9110 15: with no page (no VM, or a template that raised) the
    // bodyless status goes out instead.
    struct ErrorAnswer {
        const Resp &prefix;
        const Resp &bodyless;
        uint16_t status;
        int media;
        const ErrorPages::Fields &fields;
        bool head_only;
    };
    void spell_error(const ErrorAnswer &entry, std::string &sink);
    // Everything borrowed points into one contiguous head, so one delta moves
    // the lot; kReqValueSpans and its size assert catch a missed member. The
    // body is held apart: it will be an O_TMPFILE that a read has to fetch.
    struct Held {
        // Everything below points into this string, so it must not move once
        // hold() has run: no append, no reserve, no swap.
        std::string head;
        // A resource that declared no reader gets a view with no content, so
        // nothing is copied; see bound_prepare.
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

        // After this the provided buffer may go back to the kernel. `target` is
        // for a view whose target lies outside the head: h2 gives a parked stream
        // its fields from one buffer and its target from another. Null says the
        // target lies in the head.
        void hold(const char *head_at, size_t head_len, const ReqView &from,
                  const std::string *target);
    };

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

    enum class Took : uint8_t {
        kNo,          // not this step's request; the straight line continues
        kNextRequest, // answered, and the pipeline may hold another
        kOwed,        // answered so far as it can be; bytes are still owed
        kClose        // answered, and the connection ends
    };

    // Not inline in feed_parse: a run that parks returns out of it and comes
    // back later, which a block in a loop body cannot do.
    struct BoundAsk {
        const void *fields;
        size_t nfields;
        const RouteSpans &spans;
        const RouteTable *table;
        int route;
        Plan *plan;
        std::string &sink;
        // A run that parks may not share these: the next request on this
        // connection would write over what the parked one still owes.
        std::string &body;
        std::string &rhdrs;
    };
    // `answered` means it spelled its own head into the sink.
    struct BoundOut {
        uint16_t status = 0;
        bool have_body = false;
        bool answered = false;
        // Read once: Accept-Encoding does not change between the zero-copy gate
        // and assemble_dynamic.
        bool accept_gzip = false;
        const char *lent = nullptr;
        size_t lent_len = 0;
    };
    // A member and not a return value: everything in the ReqView points at
    // bytes somebody else owns, and the owner has to outlive it.
    struct BoundPrep {
        ReqView rv;
        size_t zc_min = 0;
        bool accept_gzip = false;
    };
    void bound_prepare(Round &round, const BoundAsk &request_ask, BoundPrep &prep);

    // By value: the Round holds references into feed_parse's frame, which is
    // gone the moment the run stops.
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
    // One coroutine serves both protocols, so there is one place where a run
    // stops. The tails differ; the stop between them does not.
    struct RunStart {
        enum class Proto : uint8_t { kH1, kH2 };
        Proto proto = Proto::kH1;
        // proto == kH1.
        BoundStart h1{};
        // proto == kH2. Copies, because the dispatch buffers die with the round
        // that read them.
        struct H2Start {
            uint32_t stream_id = 0;
            uint16_t route = 0;
            bool head_only = false;
            flow::ReqFacts facts{};
            std::string target;
            // The run copies both into its own frame before it can stop; after that
            // the decode buffer may be reused. Null = a konst route or an asset.
            const ReqView *view = nullptr;
            const char *head_at = nullptr;
            size_t head_len = 0;
        };
        H2Start h2{};
    };
    Run run_parkable(Conn &conn, RunStart sqe, std::string *sink, Plan *plan);
    enum class ComputeRound : uint8_t {
        kNext,   // answered here; read the next request out of this buffer
        kParked, // stopped; what is left waits in the carry
        kClosed, // the answer was the connection's last
    };
    // Out of feed_parse, the hottest function in the server: a resource that
    // never said `compute` does not reach it.
    ComputeRound start_compute_round(Conn &conn, const BoundStart &sqe,
                                                               std::string *sink, Plan *plan,
                                                               size_t &off);

    // kOwed = the body is still coming, or a file is being fetched.
    Took answer_bound(Round &round, const BoundAsk &request_ask, BoundOut &out_value);
    Took bound_finish(Round &round, const BoundAsk &request_ask, BoundOut &out_value);

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
        // Same reason as DynamicBody::body.
        const std::string &body;
    };
    // Out of feed_parse so the bound tier can reach it from inside a
    // coroutine while the konst tier calls it straight.
    AnswerStep spell_answer(Round &round, Spelling spelling);

    // RFC 9110 6.3: the reactor drives openat2/statx/read. Answers whether
    // it took the round.
    bool answer_from_file(Round &round, uint16_t status, const std::string &rhdrs);

    // RFC 9110 6.3 / RFC 9111: /error_assets/ resolves against the error
    // archive, everything else against --assets.
    Took answer_from_assets(Round &round, std::string &sink, Plan *plan);
    Took answer_from_docroot(Round &round);
    void file_named_tail(Round &round);

    bool connection_fail(Conn &conn, uint16_t code, std::string &out_value, uint8_t log = 0);
    struct FileHead {
        uint16_t status;
        size_t content_length;
        bool bodyless;
    };
    void file_spell(Conn &conn, FileHead head);
    void file_prebuilt(Conn &conn, uint16_t status_code);
    bool ws_upgrade(Conn &conn, const WsUpgrade &upgrade, std::string &sink);

    bool sse_begin(Conn &conn, const SseBegin &request, std::string &sink);

    // RFC 7541 6.1/6.2.2.
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
    void h2_count_reset(Conn &conn);
    // RFC 9110 15.6.1: a run that named a file is refused, not served an
    // empty body. Inline, those lines cost h2_answer 952 bytes.
    uint16_t h2_refuse_file(Conn &conn, const ReqView *request);
    // RFC 9113 6.2.
    struct H2Headers {
        uint32_t stream_id;
        bool end_stream;
        std::span<const unsigned char> block;
    };
    bool h2_dispatch(Conn &conn, const H2Headers &headers, std::string &sink);
    // RFC 9113 5.1.2, 8.7: false when the stream was refused.
    bool h2_body_file_open(Conn &conn, H2Stream &stx, uint32_t stream_id, std::string &sink);
    struct H2Connect {
        uint32_t stream_id;
        std::string_view method;
        std::string_view protocol;
        std::string_view path;
        const struct phr_header *fields;
        size_t nfields;
        const http::ReqValues *vals;
    };
    static size_t h2_fields_of_parked(const H2Stream &stream,
                               std::array<struct phr_header, kH2FieldSlots> &header_vector);
    bool h2_serve_parked(Conn &conn, H2Stream &stream, std::string &sink, bool complete);
    // True = a run was waiting on it, so the stream must not be served a
    // second time.
    bool h2_body_ready(Conn &conn, uint32_t stream_id);
    bool h2_extended_connect(Conn &conn, const H2Connect &request_ask, std::string &sink);
    struct Parked {
        std::string_view target;
        ReqView &view;
        // The view only points at the captures, so they live in the caller's
        // frame beside it.
        RouteSpans &spans;
    };
    const ReqView *h2_parked_view(Conn &conn, Parked bytes);
    // The :path is still live only here.
    struct H2Logged {
        const flow::ReqFacts &facts;
        std::string_view target;
    };
    void h2_log(Conn &conn, const H2Logged &logged);
    // RFC 9113 8.1. `target` rides beside `req` because a 404 names what was
    // not found, and that is the case where there is no ReqView.
    struct H2Request {
        uint32_t stream_id;
        const flow::ReqFacts &facts;
        const http::ReqValues *vals;
        const ReqView *req;
        std::string_view target;
        uint16_t route;
        bool head_only;
        // A run that can stop copies this range into its frame and rebases the
        // view onto the copy. Null: a run that stops answers from the head alone.
        const char *head_at = nullptr;
        size_t head_len = 0;
        // A stream served while its DATA still comes says false: the walk stops
        // at the first node that reads content, and the stream is not half closed.
        bool complete = true;
        // Null for kNoRoute.
        const Bundle *bundle = nullptr;
    };
    static bool h2_can_stop(const Bundle *block);
    struct H2Produced;
    void h2_produce(Conn &conn, const H2Request &request, bool can_park, H2Produced &bytes);
    void h2_after_run(Conn &conn, const H2Request &request, H2Produced &bytes, uint16_t status);
    bool h2_answer(Conn &conn, const H2Request &request, std::string &sink);
    // Only a resource that declared `compute` or `watch` can stop, and only
    // that one pays for a frame.
    enum class H2Served : uint8_t { kAnswered, kParked, kClosed };
    H2Served h2_serve(Conn &conn, const H2Request &request, std::string &sink);
    // WHATWG HTML over RFC 9113: sse_open runs the resource's initialize,
    // and that reads `request`.
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
    // RFC 8441: a WebSocket on one h2 stream, opened by the extended CONNECT.
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
    bool h2_frame(Conn &conn, const H2Request &request, std::string &sink, H2Produced &bytes);
    void h2_flush_pending(Conn &conn, std::string &sink, Plan *plan);
    void h2_build_asset_blocks(AssetEntry &entry);
    void h2_build_asset_shared();
    // RFC 9113 6.1/6.9: the window is the half-open span of the wire body.
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
        bool tls = false;
        // RFC 9110 15.5.14: conf.max_body.
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
    // The pictures an error page names, under their own reserved prefix,
    // mounted whether or not --assets is.
    Assets *error_assets_ = nullptr;
    std::vector<H2Block> h2_store_;
    H2Block h2_asset405_;
    H2Block h2_asset406_;
    Assets *assets_ = nullptr;
    const MimeDb *mime_ = nullptr;
    // --listings: a directory target is the listing application's.
    bool listings_ = false;
    size_t zc_min_ = kZeroCopyDefault;
    size_t map_min_ = kFileMapDefault;
    size_t send_chunk_ = file_send_chunk(60);
    Logger alog_;
    Logger elog_;
    uint16_t alog_status_ = 0;
    size_t alog_bytes_ = 0;
    std::string body_;
    std::string gz_body_;
    // RFC 9110 6.3: empty keeps every prebuilt path byte-identical.
    std::string rhdrs_;
    char date_[29] = {};
};

// Two functions because a run can stop between them. One framer either
// way, so the parked path and the straight path spell one answer.
struct Http1::H2Produced {
    const Bundle *b = nullptr;
    const std::array<uint16_t, 600> *idx = nullptr;
    uint16_t status = 0;
    bool have_body = false;
    bool dynamic = false;
    // Not yet owned by a stream, so every path out of the framing still has
    // to place or free it.
    mrb_state *lent_mrb = nullptr;
    mrb_value lent_v = {};
    const char *lent = nullptr;
    size_t lent_len = 0;
    bool lent_have = false;
    // A parked run hands in a pair of its own, because the writer's would be
    // written over by the next request.
    std::string *body = nullptr;
    std::string *rhdrs = nullptr;
};
inline bool Http1::h2_can_stop(const Bundle *block)
{
    return block != nullptr && block->bound && block->res != nullptr &&
           ((block->res->compute | block->res->watch) != 0 ||
            (block->res->value_jobs | block->res->value_watch) != 0);
}
} // namespace webmachine

#endif
