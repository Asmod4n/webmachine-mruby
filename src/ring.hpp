// The reactor: one thread, one io_uring, and every piece of state hung
// off one instance - no globals, so N instances could exist someday,
// though no line here knows about threads.
#ifndef WEBMACHINE_RING_HPP
#define WEBMACHINE_RING_HPP

#include <liburing.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace webmachine {

// Slot count == the sparse direct-descriptor table size: a connection's
// id IS its direct descriptor index, so lookup is an array index.
inline constexpr uint32_t kMaxConns = 4096;
// Pool geometry measured in the old tree as not moving the profile
// (2048 x 4096 vs ladders: null result), so the simple shape stays.
inline constexpr uint32_t kBufCount = 2048;  // power of two: ring mask
inline constexpr uint32_t kBufSize = 4096;
inline constexpr uint16_t kBufGroup = 0;

struct Conn {
  // Read on every event before anything else.
  bool live = false;
  bool sending = false;          // `out` is borrowed by the kernel
  bool close_after_send = false;
  uint16_t gen = 0;  // stale-CQE guard: slot reuse bumps it, old ops miss
  size_t sent = 0;   // bytes of `out` the kernel has taken so far

  // Two buffers, not one: `out` is BORROWED by an in-flight send (its
  // pointer is in the SQE), so nothing may append to or clear it until
  // the send's CQE - appends land in `next`, the swap happens when the
  // send drains. Capacity survives clear(); a warm slot allocates
  // nothing.
  std::string out;
  std::string next;
};

struct RingConfig {
  const char* unix_path = nullptr;  // exactly one of unix_path / port
  int port = 0;
  // Echo received bytes instead of answering 200: the byte-proof mode
  // the small-segment bintest drives.
  bool echo = false;
};

class Ring {
 public:
  Ring() = default;
  Ring(const Ring&) = delete;
  Ring& operator=(const Ring&) = delete;
  ~Ring();

  // False leaves the reason in err. Reads WM_BUNDLE (debug knob, only
  // ever narrowing): recv bundles default to the kernel's feature bit;
  // one known-broken kernel (container 6.18.5-fc) violates the
  // dense-fill contract and sets WM_BUNDLE=0.
  bool init(const RingConfig& cfg, char* err, size_t errlen);

  [[noreturn]] void run();

  // Requests answered, for the counter line a bench run prints.
  uint64_t served() const { return served_; }

 private:
  void tick();
  void handle(struct io_uring_cqe* cqe);
  void on_accept(struct io_uring_cqe* cqe);
  void on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe);
  void on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe);
  void arm_accept();
  void arm_recv(uint32_t idx);
  void arm_send(uint32_t idx);
  void begin_close(uint32_t idx);
  // Never returns null: a full SQ is submitted and retried once, and a
  // ring that cannot take an SQE after that is a broken ring - checked,
  // reported on stderr, process exits (there is no connection to blame).
  struct io_uring_sqe* sqe();

  struct io_uring ring_ {};
  bool ring_up_ = false;
  bool bundles_ = false;
  bool echo_ = false;
  int listen_fd_ = -1;
  char* pool_ = nullptr;  // kBufCount * kBufSize, mmap'd once
  struct io_uring_buf_ring* buf_ring_ = nullptr;
  // Buffers consumed this tick, handed back (advance-only: the ring
  // entries were written once and consumption strictly rotates) at the
  // top of the NEXT tick - a Read's bytes stay valid until then.
  unsigned replenish_ = 0;
  std::vector<Conn> conns_;
  // Connections whose multishot recv ended this tick and must be
  // re-armed after the batch (their prep would race the buffer advance).
  std::vector<uint32_t> rearm_;
  uint64_t served_ = 0;
};

}  // namespace webmachine

#endif
