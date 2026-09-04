// Design decisions live in .DESIGN.md, filed under what each comment names.
//
// #80: the compute pool a Promise is answered by.
//
// Watcher is this file's sibling and the other half of the same idea: a
// watcher answers the SAME question again until somebody disarms it, and
// it watches a descriptor. A promise is asked once, it is answered once,
// and what answers it is a thread - because the work is not waiting for
// a descriptor, it is arithmetic that would otherwise be done on the
// reactor's core. argon2 is the first of it: ~40 ms, which is every
// other connection on this core stopped for that long.
//
// The queue between the two is io_uring's own. A worker blocks in
// io_uring_wait_cqe on a ring of its own; the reactor posts work into it
// with IORING_OP_MSG_RING, and the worker posts the answer back the same
// way. So there is no ring buffer here to get the memory ordering right
// in, no condition variable, no eventfd beside the queue to wake anyone
// - and the answer arrives at the reactor as an ORDINARY completion,
// which is what makes a promise resolved by a thread indistinguishable
// from one resolved by a disk.
#include "webmachine.hpp"

#include <liburing.h>

#include <pthread.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace webmachine {
namespace {

// What crosses MSG_RING is user_data (64 bits) and a 32-bit result, and
// nothing else - no payload. So a job is named by its slot, and the slot
// carries the work. The slots are allocated once; a promise never
// allocates while the server is answering.
struct Slot {
  ComputePool::Fn fn = nullptr;
  void* arg = nullptr;
  // The reactor's own tag for this promise: what its completion will
  // carry, so the reactor knows whose answer arrived. The pool never
  // looks inside it.
  uint64_t answer = 0;
  bool busy = false;
};

// user_data on the WORKER's ring. Not a webmachine tag - this side is
// the pool's own, and the only two things it says are "here is slot i"
// and "stop".
constexpr uint64_t kStopJob = ~static_cast<uint64_t>(0);
// MSG_RING answers TWICE: the target ring gets the message, and the
// sender's own ring gets a completion for having sent it. A worker
// therefore sees its own answer come back, and anything that is not a
// job index has to be stepped over rather than used as one.
constexpr uint64_t kSent = ~static_cast<uint64_t>(1);

}  // namespace

struct ComputePool::Impl {
  std::vector<struct io_uring> rings;
  std::vector<std::thread> threads;
  std::vector<Slot> slots;
  // Round-robin, and that is enough: every job in this pool is a
  // password hash with fixed m and t, so they all cost the same. A
  // shortest-queue choice would compute an answer the caller already
  // knows - the counts would differ by at most one.
  unsigned next = 0;
  struct io_uring* home = nullptr;
  bool up = false;
};

// One worker: block, run what the slot names, answer, repeat. It never
// touches an mrb_state - the VM is not thread-safe, and a job that
// wanted one would be a job for the reactor's core.
void ComputePool::worker(Impl* impl, unsigned me) {
  struct io_uring* ring = &impl->rings[me];
  // A thread with no name is a number in a backtrace, and a backtrace
  // taken while a promise is being answered is exactly the one that has
  // to say WHICH worker. Linux takes 16 bytes with the terminator, so
  // the number has to fit inside that - it is not a place to be
  // generous with words.
#if defined(__linux__)
  {
    char name[16];
    std::snprintf(name, sizeof(name), "wm-promise%u", me);
    pthread_setname_np(pthread_self(), name);
  }
#endif
  for (;;) {
    struct io_uring_cqe* cqe = nullptr;
    const int rc = io_uring_wait_cqe(ring, &cqe);
    if (rc < 0) {
      if (rc == -EINTR) continue;
      return;
    }
    const uint64_t job = cqe->user_data;
    io_uring_cqe_seen(ring, cqe);
    if (job == kStopJob) return;
    // Our own send, or anything else that is not one of our slots.
    if (job >= impl->slots.size()) continue;

    Slot& s = impl->slots[static_cast<size_t>(job)];
    if (s.fn != nullptr) s.fn(s.arg);

    // The answer goes home as a completion. The reactor reads the slot
    // only after this arrives, and wrote it only before the job was
    // sent, so the ring's own ordering is the whole synchronisation -
    // there is no lock here because there is nothing two threads touch
    // at the same time.
    struct io_uring_sqe* sqe = nullptr;
    while ((sqe = io_uring_get_sqe(ring)) == nullptr) io_uring_submit(ring);
    io_uring_prep_msg_ring(sqe, impl->home->ring_fd, 0, s.answer, 0);
    io_uring_sqe_set_data64(sqe, kSent);
    io_uring_submit(ring);
  }
}

// Ready, or a reason. A pool that cannot be built is a startup refusal,
// not a degraded mode: the alternative is hashing a password on the
// reactor's core, which is worse than not starting.
const char* ComputePool::start(unsigned workers, unsigned depth, struct io_uring* home) {
  if (impl_ != nullptr) return "the pool is already up";
  if (workers == 0 || home == nullptr) return "a pool needs a worker and a ring to answer to";

  auto* impl = new Impl();
  impl->home = home;
  impl->rings.resize(workers);
  impl->slots.resize(static_cast<size_t>(workers) * depth);

  for (unsigned i = 0; i < workers; i++) {
    const int rc = io_uring_queue_init(depth < 8 ? 8 : depth, &impl->rings[i], 0);
    if (rc < 0) {
      for (unsigned j = 0; j < i; j++) io_uring_queue_exit(&impl->rings[j]);
      delete impl;
      return std::strerror(-rc);
    }
  }
  for (unsigned i = 0; i < workers; i++) {
    impl->threads.emplace_back([impl, i] { ComputePool::worker(impl, i); });
  }
  impl->up = true;
  impl_ = impl;
  return nullptr;
}

void ComputePool::stop() {
  if (impl_ == nullptr) return;
  Impl* impl = impl_;
  for (size_t i = 0; i < impl->rings.size(); i++) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&impl->rings[i]);
    if (sqe != nullptr) {
      // A ring may message itself, which is how a worker is told to go
      // without a second channel for the telling.
      io_uring_prep_msg_ring(sqe, impl->rings[i].ring_fd, 0, kStopJob, 0);
      io_uring_submit(&impl->rings[i]);
    }
  }
  for (std::thread& t : impl->threads) {
    if (t.joinable()) t.join();
  }
  for (struct io_uring& r : impl->rings) io_uring_queue_exit(&r);
  delete impl;
  impl_ = nullptr;
}

bool ComputePool::submit(Fn fn, void* arg, uint64_t answer) {
  if (impl_ == nullptr) return false;
  Impl* impl = impl_;
  // A free slot, or no. Full means every worker is busy with a full
  // queue behind it, and the caller decides what that means - this
  // layer does not invent a refusal for it.
  size_t at = impl->slots.size();
  for (size_t i = 0; i < impl->slots.size(); i++) {
    if (!impl->slots[i].busy) {
      at = i;
      break;
    }
  }
  if (at == impl->slots.size()) return false;

  Slot& s = impl->slots[at];
  s.fn = fn;
  s.arg = arg;
  s.answer = answer;
  s.busy = true;

  const unsigned to = impl->next++ % static_cast<unsigned>(impl->rings.size());
  struct io_uring_sqe* sqe = io_uring_get_sqe(impl->home);
  if (sqe == nullptr) {
    s.busy = false;
    return false;
  }
  io_uring_prep_msg_ring(sqe, impl->rings[to].ring_fd, 0, static_cast<uint64_t>(at), 0);
  // The submission itself owes no completion to anyone: the answer comes
  // from the worker, not from the act of sending.
  io_uring_sqe_set_data64(sqe, detail::tag(detail::kPromise, 0, 0));
  return true;
}

void ComputePool::release(uint64_t answer) {
  if (impl_ == nullptr) return;
  for (Slot& s : impl_->slots) {
    if (s.busy && s.answer == answer) {
      s.busy = false;
      s.fn = nullptr;
      s.arg = nullptr;
      return;
    }
  }
}

unsigned ComputePool::workers() const {
  return impl_ == nullptr ? 0 : static_cast<unsigned>(impl_->rings.size());
}

}  // namespace webmachine
