#ifndef WEBMACHINE_RING_SETUP_HPP
#define WEBMACHINE_RING_SETUP_HPP

#include "webmachine.hpp"

namespace webmachine
{
inline constexpr uint32_t kMaxListeners = 16;
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
// uploads over kBodySpill at the same time. It bounds how many bodies
// this process holds in files at once, and nothing else - it is not
// taken off the connection table, because RLIMIT_NOFILE already counts
// every descriptor this process holds, a direct one as much as an
// ordinary one.
inline constexpr uint32_t kBodyFilesMax = 1024;
// The locked-memory limit this process runs under, with the soft limit
// raised to the hard one first. A ring's SQ and CQ pages are charged to
// it. Every refusal of the two limit calls raises.
uint64_t raise_memlock(mrb_state *mrb);

// Submission entries a ring asks for. The queue and its completion
// queue are locked memory, and the kernel charges those pages to the
// user, so what fits is not this process's to compute - the ring asks
// from here downward and the kernel answers.
inline constexpr unsigned kSqEntriesMax = 512;

// An io_uring and nothing else: no buffers, no descriptor table, no
// listeners.
//
// One of these comes up before the configuration is read, so that every
// file the start opens - the mime database, the asset archive, the
// error pages, the docroot - goes through a ring rather than through a
// syscall that blocks the thread. slipstreamIO answers the same API
// where the kernel refuses io_uring, so a ring exists on every host
// this server starts on, and "before the ring" is only the lines that
// fork and exec webmachine-logd.
//
// That one dies when the configuration stands. It cannot become the
// reactor's: [tune] sq_entries is the operator's and is read through
// it, so the queue that carries the answers is made after the answer is
// known. Ring::init makes its own with the same call.
struct BootQueue {
    struct io_uring ring {
    };
    unsigned entries = 0;
    bool up = false;
};

// Bring one up, halving the queue until the kernel takes it. `want` is
// kSqEntriesMax at the start, or what the operator named once that is
// known. Every refusal raises.
void boot_queue_up(mrb_state *mrb, BootQueue &queue, unsigned want);

// And close it. A queue that was handed on (up set to false by the
// taker) is not closed twice.
void boot_queue_down(BootQueue &queue);

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
// of whatever finally stands. Every refusal of the two limit calls raises.
uint64_t raise_nofile(mrb_state *mrb);

// A listener the reactor answers on. It carries no certificate: this
// build has no record layer, so every listener serves cleartext. The
// configuration still names TLS and server.cpp refuses it by name - see
// listener_tls_refuse - so nothing reaches here wanting it.
struct ListenerSpec {
    const char *unix_path = nullptr;
    int port = 0;
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
    // The rings of the threads that answer, when this ring only accepts.
    // Empty means this ring answers what it accepts, which is the shape
    // every build had before threads.
    const int *worker_ring_fds = nullptr;
    uint32_t nworkers = 0;
    // True on a ring that accepts nothing: it has no listener, and every
    // connection it answers arrived from an acceptor by IORING_OP_MSG_RING.
    bool takes_no_listener = false;
    // How many rings share the locked-memory budget with this one. The
    // kernel charges a ring's memory to the user rather than to the
    // process, so this counts the rings of every process this server
    // starts: N + 1 for --threads=N.
    uint32_t rings_in_process = 1;
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

// #113: user_data is the address of the record that armed the
// operation. The record says its kind and names its connection, so
// nothing here is packed into bits and nothing is indexed by a slot.

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

// user_data on a ring that receives connections from an acceptor. The
// value is not a pointer into anything: IORING_OP_MSG_RING carries one
// word of ours to the other ring, and these two say "a connection
// arrived, and cqe->res is the descriptor the table allocated for it".
// They are small enough that no Op can ever live at those addresses.
enum : uint64_t {
    kAdoptUnix = 1,
    kAdoptTcp = 2,
    // And the word that ends such a ring: the acceptor read the stop
    // signal, and says so to every ring it feeds.
    kAdoptStop = 3
};

// Which stage of the setup chain a failing CQE belongs to.
const char *stage_name(uint32_t conn);
} // namespace detail

} // namespace webmachine

#endif
