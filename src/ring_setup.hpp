//
// What the reactor is set up with: the descriptor budget, the listener
// spelling, RingConfig, and the tags a completion carries. Read by
// ring.hpp, docroot.cpp, server.cpp and compute_task.cpp.
#ifndef WEBMACHINE_RING_SETUP_HPP
#define WEBMACHINE_RING_SETUP_HPP

#include "webmachine.hpp"

namespace webmachine
{
inline constexpr uint32_t kMaxListeners = 16;
inline constexpr uint32_t kFdReserve = 128;
// RFC 9110 6.4: how many request body files this process holds open at
// once. A body of kBodySpill or more lives in a file, and so does every
// body for a resource that saves it, whatever its length. That file is
// an ordinary descriptor outside the fixed table. One h1 connection
// holds one, and one h2 connection holds up to kH2SpillFilesMax. No
// per-connection number bounds the sum; this constant does. The budget
// below reserves it, so a body file never takes the descriptor that an
// asset, a log or the docroot opens next. Over it the server refuses
// the body as load: 503 on h1, REFUSED_STREAM on h2.
//
// The size: 1024 is 64 h2 connections at kH2SpillFilesMax, or 1024 h1
// uploads over kBodySpill at the same time. The server raises itself to
// the hard limit (raise_nofile). Under the 524288 systemd gives a
// service, and the 1048576 a container gets, this costs 0.2 % of the
// connections. A limit under 1169 - this, kFdReserve, kMaxListeners and
// one connection - refuses to start, and the message names the numbers.
inline constexpr uint32_t kBodyFilesMax = 1024;
inline constexpr uint32_t kFixedTableKernelMax = 1u << 20;

// A ring's SQ/CQ pages are locked memory; failing to raise is not a
// reason not to start.
void raise_memlock();

// The one arithmetic with two consumers: the server sizes itself with it,
// webmachine-tune.sh only prints it.
// The file-descriptor budget one process has: what RLIMIT_NOFILE allows,
// and how many descriptors something other than a connection takes:
// kFdReserve for the process's own, kBodyFilesMax for request bodies in
// files, and the listeners.
struct FdBudget {
    uint64_t nofile_limit;
    uint32_t extra_slots = 0;
};

uint32_t derive_max_conns(FdBudget b);

// #80: jobs in flight per worker. Small on purpose - a compute task is work
// this process decided not to do on its core, and a deep queue in front
// of it only hides that every worker is already busy.
inline constexpr unsigned kComputeDepth = 16;
inline constexpr uint32_t kBufCount = 2048;
inline constexpr uint32_t kBufSize = 4096;
inline constexpr uint16_t kBufGroup = 0;
static_assert((kBufCount & (kBufCount - 1)) == 0, "buffer walk wraps by mask");
static_assert(static_cast<size_t>(kBufCount) <= SIZE_MAX / kBufSize,
              "pool size arithmetic must not overflow");

// Soft to hard, ceiling fs.nr_open, once at init - the capacity falls out
// of whatever finally stands.
uint64_t raise_nofile();

struct ListenerSpec {
    const char *unix_path = nullptr;
    int port = 0;
    // The PEM this listener answers with, already read - server.cpp owns
    // the bytes and outlives the ring. Both or neither: a listener with a
    // certificate is a TLS listener, and there is no other switch.
    const char *cert_pem = nullptr;
    size_t cert_len = 0;
    const char *key_pem = nullptr;
    size_t key_len = 0;
};

// What the reactor needs and nothing else - already resolved, already
// merged. Same names as the operator's knobs (see Config), so a value can
// be followed from the file to the SQE without changing what it is called.
struct RingConfig {
    ListenerSpec listeners[kMaxListeners] = {};
    uint32_t nlisteners = 0;
    int log_fd = -1;
    int err_fd = -1;
    unsigned sq_entries = 0;
    int backlog = 0;
    int header_timeout = 0;
    int send_timeout = 0;
    int idle_timeout = 0;
    int stop_fd = -1;
    // The VM to raise into when the reactor cannot go on. Required - init()
    // refuses without it, because the alternative is a library that ends
    // somebody else's process. See Ring::fatal.
    mrb_state *mrb = nullptr;
};

namespace detail
{
enum : uint8_t {
    kAccept = 1,
    kRecv = 2,
    kSend = 3,
    kClose = 4,
    kSetup = 5,
    kStop = 6,
    kShutdown = 7,
    kMeminfo = 8,
    kLog = 9,
    kPeer = 10,
    // response.file: one kind per stage, so the tag needs no second field.
    kFileOpen = 11,
    kFileStat = 12,
    kFileRead = 13,
    kFileClose = 14,
    // #30: a watcher firing. This one does need a second field - a
    // connection may run several - and bits 48..55 of the tag were never
    // spoken for, so the slot goes there and the layout is unchanged.
    kWatch = 15,
    // The handover, one kind per setsockopt so a failing CQE says which:
    // TCP_ULP first, then the two crypto_info blobs.
    kTlsUlp = 16,
    kTlsTx = 17,
    kTlsRx = 18,
    // close_notify on the way out; nothing waits for it, the tag only
    // keeps its completion from being read as some other slot's.
    kTlsBye = 19,
    // A send key turned before its record limit. The completion matters:
    // nothing more may go out under the old key.
    kTlsTxKey = 20,
    // #80: a compute worker answered. The tag is the connection's, so the
    // generation guard every other op relies on discards an answer whose
    // connection is already gone.
    kComputeTask = 21,
    // #80: a compute job's deadline. The tag names the worker, not a
    // connection, because what it acts on is the worker's VM. Bits 48..55
    // carry the job number, so a timeout for a job that already answered
    // interrupts nothing.
    kComputeDeadline = 22,
    // A poll_remove for a watcher whose deadline passed. Nothing reads
    // its completion.
    kPollRemove = 23,
    // #80: a worker began a job. The reactor arms the job's deadline
    // from here, so the deadline is execution time and not queue time.
    kComputeStarted = 24,
    // RFC 9110 6.4: one write of a request body into its spill file. The
    // tag is the connection's, and one write of this kind flies per
    // connection, so no second field is needed to say which body it is.
    kSpillWrite = 25
};

// user_data: kind(8) | gen(16) | idx(32); gen guards a reused slot.
uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx);
// #30: which watcher, on top of which connection - 8 bits of the tag,
// so kMaxWatchers of them (declared further up, where Conn needs it).
uint64_t watch_tag(uint16_t gen, uint32_t idx, uint8_t slot);
uint8_t watch_slot(uint64_t ud);
// #30: the same 8 bits for a compute job. A value round hands over
// several at one stop, so an answer has to say which one it is.
// Four bits name the stopped run and four name its job, so one byte
// carries both: a connection holds up to 16 stopped runs - one per h2
// stream - and a run hands over up to four jobs at a stop.
// Both name one job: the pool's slot and which taking of it.
uint64_t compute_deadline_tag(unsigned slot, uint16_t gen);
uint64_t compute_started_tag(unsigned slot, uint16_t gen);
// The connection index takes 24 bits, which is more than the fixed
// file table allows, and the top byte of that word names which taking
// of the park slot this job belongs to.
static_assert(kFixedTableKernelMax <= (1u << 24), "a connection index must fit 24 bits");
uint64_t compute_task_tag(uint16_t gen, uint32_t idx, uint8_t park, uint8_t job, uint8_t park_gen);

enum : uint32_t {
    kStSocket = 1,
    kStSockopt = 2,
    kStBind = 3,
    kStListen = 4,
    kStName = 5,
    // The unlink of a unix path at the ring exit, so the exit can tell
    // its completion from a listener close ahead of it.
    kStUnlink = 6
};

// Which stage of the setup chain a failing CQE belongs to.
const char *stage_name(uint32_t st);
} // namespace detail

} // namespace webmachine

#endif
