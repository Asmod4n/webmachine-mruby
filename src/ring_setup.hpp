//
// What the reactor is set up with: the descriptor budget, the listener
// spelling, RingConfig, and the tags a completion carries. Read by
// ring.hpp, server.cpp and compute_task.cpp.
#ifndef WEBMACHINE_RING_SETUP_HPP
#define WEBMACHINE_RING_SETUP_HPP

#include "webmachine.hpp"

namespace webmachine {
inline constexpr uint32_t kMaxListeners = 16;
inline constexpr uint32_t kFdReserve = 128;
inline constexpr uint32_t kFixedTableKernelMax = 1u << 20;

// A ring's SQ/CQ pages are locked memory; failing to raise is not a
// reason not to start.
inline void raise_memlock() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return;
  if (rl.rlim_cur == rl.rlim_max) return;
  struct rlimit want {rl.rlim_max, rl.rlim_max};
  (void)::setrlimit(RLIMIT_MEMLOCK, &want);
}

// The one arithmetic with two consumers: the server sizes itself with it,
// webmachine-tune.sh only prints it.
// The file-descriptor budget one process has: what RLIMIT_NOFILE allows,
// and how many descriptors something other than a connection will take.
struct FdBudget {
  uint64_t nofile_limit;
  uint32_t extra_slots = 0;
};

inline uint32_t derive_max_conns(FdBudget b) {
  const uint64_t nofile_limit = b.nofile_limit;
  const uint32_t extra_slots = b.extra_slots;
  const uint64_t taken = static_cast<uint64_t>(kFdReserve) + kMaxListeners + extra_slots;
  if (nofile_limit <= taken) return 0;
  uint64_t n = nofile_limit - taken;
  if (n + kMaxListeners + extra_slots > kFixedTableKernelMax) {
    n = kFixedTableKernelMax - kMaxListeners - extra_slots;
  }
  return static_cast<uint32_t>(n);
}

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
inline uint64_t raise_nofile() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
#ifdef IO_URING_FD_CEILING
  rlim_t target = static_cast<rlim_t>(IO_URING_FD_CEILING - 1);
  if (target > rl.rlim_max) target = rl.rlim_max;
  if (rl.rlim_cur != target) {
    struct rlimit want {target, rl.rlim_max};
    (void)::setrlimit(RLIMIT_NOFILE, &want);
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
  }
  const uint64_t cur = static_cast<uint64_t>(rl.rlim_cur);
  return cur < IO_URING_FD_CEILING ? cur : IO_URING_FD_CEILING - 1;
#else
  rlim_t target = rl.rlim_max;
  if (target == RLIM_INFINITY) {
    uint64_t nr_open = 1u << 20;
    if (std::FILE* f = std::fopen("/proc/sys/fs/nr_open", "re")) {
      unsigned long long v = 0;
      if (std::fscanf(f, "%llu", &v) == 1 && v > 0) nr_open = v;
      std::fclose(f);
    }
    target = static_cast<rlim_t>(nr_open);
  }
  if (rl.rlim_cur < target) {
    struct rlimit want {target, rl.rlim_max};
    (void)::setrlimit(RLIMIT_NOFILE, &want);
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
  }
  return static_cast<uint64_t>(rl.rlim_cur);
#endif
}

struct ListenerSpec {
  const char* unix_path = nullptr;
  int port = 0;
  // The PEM this listener answers with, already read - server.cpp owns
  // the bytes and outlives the ring. Both or neither: a listener with a
  // certificate is a TLS listener, and there is no other switch.
  const char* cert_pem = nullptr;
  size_t cert_len = 0;
  const char* key_pem = nullptr;
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
  mrb_state* mrb = nullptr;
};

namespace detail {
enum : uint8_t {
  kAccept = 1, kRecv = 2, kSend = 3, kClose = 4, kSetup = 5, kStop = 6, kShutdown = 7,
  kMeminfo = 8, kLog = 9, kPeer = 10,
  // response.file: one kind per stage, so the tag needs no second field.
  kFileOpen = 11, kFileStat = 12, kFileRead = 13, kFileClose = 14,
  // #30: a watcher firing. This one does need a second field - a
  // connection may run several - and bits 48..55 of the tag were never
  // spoken for, so the slot goes there and the layout is unchanged.
  kWatch = 15,
  // The handover, one kind per setsockopt so a failing CQE says which:
  // TCP_ULP first, then the two crypto_info blobs.
  kTlsUlp = 16, kTlsTx = 17, kTlsRx = 18,
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
  kComputeStarted = 24
};


// user_data: kind(8) | gen(16) | idx(32); gen guards a reused slot.
inline uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
}
// #30: which watcher, on top of which connection - 8 bits of the tag,
// so kMaxWatchers of them (declared further up, where Conn needs it).
inline uint64_t watch_tag(uint16_t gen, uint32_t idx, uint8_t slot) {
  return tag(kWatch, gen, idx) | (static_cast<uint64_t>(slot) << 48);
}
inline uint8_t watch_slot(uint64_t ud) { return static_cast<uint8_t>(ud >> 48); }
// #30: the same 8 bits for a compute job. A value round hands over
// several at one stop, so an answer has to say which one it is.
// Four bits name the stopped run and four name its job, so one byte
// carries both: a connection holds up to 16 stopped runs - one per h2
// stream - and a run hands over up to four jobs at a stop.
// Both name one job: the pool's slot and which taking of it.
inline uint64_t compute_deadline_tag(unsigned slot, uint16_t gen) {
  return tag(kComputeDeadline, gen, static_cast<uint32_t>(slot));
}
inline uint64_t compute_started_tag(unsigned slot, uint16_t gen) {
  return tag(kComputeStarted, gen, static_cast<uint32_t>(slot));
}
// The connection index takes 24 bits, which is more than the fixed
// file table allows, and the top byte of that word names which taking
// of the park slot this job belongs to.
static_assert(kFixedTableKernelMax <= (1u << 24), "a connection index must fit 24 bits");
inline uint64_t compute_task_tag(uint16_t gen, uint32_t idx, uint8_t park, uint8_t job,
                                 uint8_t park_gen) {
  const uint8_t both = static_cast<uint8_t>((park << 4) | (job & 0x0f));
  const uint32_t word = (idx & 0xffffffu) | (static_cast<uint32_t>(park_gen) << 24);
  return tag(kComputeTask, gen, word) | (static_cast<uint64_t>(both) << 48);
}

enum : uint32_t { kStSocket = 1, kStSockopt = 2, kStBind = 3, kStListen = 4, kStName = 5 };

// Which stage of the setup chain a failing CQE belongs to.
inline const char* stage_name(uint32_t st) {
  switch (st) {
    case kStSocket: return "socket";
    case kStSockopt: return "setsockopt";
    case kStBind: return "bind";
    case kStListen: return "listen";
    case kStName: return "getsockname";
  }
  return "?";
}
}

}

#endif
