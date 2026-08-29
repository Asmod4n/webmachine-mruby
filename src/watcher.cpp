// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/variable.h>

#include <liburing.h>
#include <poll.h>

namespace webmachine {
namespace {

// What a watcher IS, and it is deliberately not much: a mask, a flag, and
// the handle the server armed it under. None of these is a Ruby object,
// so none of them belongs in the instance-variable table - only `source`
// and `block` do, because those are the two things the GC has to see.
//
// RData carries both (include/mruby/data.h: an iv table AND a data
// pointer), so this costs one small allocation and leaves the iv table
// holding exactly the two references that must not be collected.
struct WatcherData {
  // THE DESCRIPTOR, taken once at construction and never asked for
  // again. It has to be here rather than fetched from the source when
  // wanted, because the place that needs it most is the destructor
  // below - and calling .fileno on a Ruby object while the GC is
  // sweeping is not something to attempt.
  //
  // `int` and not a platform handle type, and that survives Windows
  // too: enough POSIX software was ported through shims that never
  // learned what a SOCKET is, so the C runtime hands out int
  // descriptors there as well. Nothing here has to change when IOCP
  // arrives underneath.
  int fd = -1;
  // #30: WHICH watcher, on the connection running it. The one name a
  // watcher has: it is the key it is filed under and the field the
  // completion carries back, so nothing has to be translated between
  // the ring and the hash.
  int slot = -1;
  // POLLIN, POLLOUT, or both. Stored as poll's own bits rather than the
  // symbol, because that is what the ring is handed and what comes back.
  unsigned events = POLLIN;
  // Said by the user, read by the server after the block returns. A
  // watcher runs until this is set - running on is the default, and
  // stopping is the one thing that needs saying.
  bool aborted = false;
  // Armed, and on which ring - so the destructor can take the poll off
  // again without asking anybody anything.
  struct io_uring* ring = nullptr;
  bool armed = false;
};

// The safety net, NOT the normal path. A watcher reaching the GC still
// armed means nobody tidied up - a raise on the way out of a callback is
// how that happens - and then the poll has to come off the ring here, or
// it keeps firing at a connection that is gone.
//
// In the ordinary case this does nothing: the connection cancels the
// poll itself and empties the CDATA, so by the time the sweep arrives
// there is no pointer left.
void watcher_free(mrb_state*, void* p) {
  auto* d = static_cast<WatcherData*>(p);
  if (d == nullptr) return;
  if (d->armed && d->ring != nullptr && d->fd >= 0) {
    struct io_uring_sqe* s = io_uring_get_sqe(d->ring);
    if (s != nullptr) {
      // By DESCRIPTOR, which is all this destructor knows and all it
      // needs to: it takes off whatever is armed on that fd.
      io_uring_prep_cancel_fd(s, d->fd, IORING_ASYNC_CANCEL_ALL);
      io_uring_sqe_set_data64(s, 0);
      io_uring_submit(d->ring);
    }
  }
  delete d;
}

const struct mrb_data_type watcher_type = {"Webmachine::Watcher", watcher_free};

WatcherData* live(mrb_state* mrb, mrb_value self) {
  auto* d = static_cast<WatcherData*>(DATA_PTR(self));
  if (d == nullptr) mrb_raise(mrb, E_WM_ERROR(mrb), "this watcher was never initialized");
  return d;
}

// :r, :w, :rw and nothing else. The ORDER menu is this short on purpose -
// what ARRIVES is a wider set (revents), and the two are not the same
// thing, which is why they do not share a name.
unsigned mask_of(mrb_state* mrb, mrb_value v) {
  if (!mrb_symbol_p(v)) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "a watcher waits for :r, :w or :rw, not %v", v);
  }
  const mrb_sym s = mrb_symbol(v);
  if (s == MRB_SYM(r)) return POLLIN;
  if (s == MRB_SYM(w)) return POLLOUT;
  if (s == MRB_SYM(rw)) return POLLIN | POLLOUT;
  mrb_raisef(mrb, E_ARGUMENT_ERROR, "a watcher waits for :r, :w or :rw, not %v", v);
  return 0;
}

mrb_value sym_of(mrb_state* mrb, unsigned mask) {
  const unsigned rw = mask & (POLLIN | POLLOUT);
  if (rw == (POLLIN | POLLOUT)) return mrb_symbol_value(MRB_SYM(rw));
  if (rw == POLLOUT) return mrb_symbol_value(MRB_SYM(w));
  return mrb_symbol_value(MRB_SYM(r));
}

// Watcher.new(source, :r) { |revents, watcher| ... }
//
// Building one ARMS NOTHING. A watcher is a description - a source, what
// to wait for, and what to do when that happens - and the server does the
// arming when a resource hands one back. Ruby never touches the ring, so
// there is nothing here that could stop the loop.
mrb_value watcher_init(mrb_state* mrb, mrb_value self) {
  mrb_value source;
  mrb_value events = mrb_symbol_value(MRB_SYM(r));
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "o|o&", &source, &events, &blk);

  // A source is something with a descriptor. Asked as a question rather
  // than assumed, so a String or a Hash is refused here - where the
  // mistake was made - and not somewhere inside the reactor.
  if (!mrb_respond_to(mrb, source, MRB_SYM(fileno))) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR,
               "a watcher watches something with a fileno, and %C has none",
               mrb_obj_class(mrb, source));
  }
  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR,
              "a watcher without a block would have nothing to do when it fires");
  }

  // Asked ONCE, here, while there is still a VM to ask in.
  const mrb_value fdv = mrb_funcall_id(mrb, source, MRB_SYM(fileno), 0);
  if (!mrb_integer_p(fdv) || mrb_integer(fdv) < 0) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "a watcher needs a descriptor, and fileno answered %v", fdv);
  }

  auto* d = new WatcherData();
  d->fd = static_cast<int>(mrb_integer(fdv));
  d->events = mask_of(mrb, events);
  mrb_data_init(self, d, &watcher_type);

  // THE iv TABLE, and only these two. Both are Ruby objects the watcher
  // outlives its caller holding: a source nobody else keeps would be
  // collected under the reactor, and a block nobody else keeps would
  // leave the watcher firing into nothing.
  mrb_iv_set(mrb, self, MRB_IVSYM(source), source);
  mrb_iv_set(mrb, self, MRB_IVSYM(block), blk);
  return self;
}

mrb_value watcher_source(mrb_state* mrb, mrb_value self) {
  return mrb_iv_get(mrb, self, MRB_IVSYM(source));
}

mrb_value watcher_block(mrb_state* mrb, mrb_value self) {
  return mrb_iv_get(mrb, self, MRB_IVSYM(block));
}

mrb_value watcher_events(mrb_state* mrb, mrb_value self) {
  return sym_of(mrb, live(mrb, self)->events);
}

// Change what this watcher waits for, from now on. The registration is
// not replaced - the server updates it in place - so readiness arriving
// while this is being said cannot fall between two chairs.
mrb_value watcher_events_set(mrb_state* mrb, mrb_value self) {
  mrb_value v;
  mrb_get_args(mrb, "o", &v);
  live(mrb, self)->events = mask_of(mrb, v);
  return v;
}

// Stop. The one word this side of the API needs, because running on is
// what a watcher does when nobody says anything.
mrb_value watcher_abort(mrb_state* mrb, mrb_value self) {
  live(mrb, self)->aborted = true;
  return self;
}

mrb_value watcher_aborted(mrb_state* mrb, mrb_value self) {
  return mrb_bool_value(live(mrb, self)->aborted);
}

}  // namespace

// The server's side of the same object. Nothing here reaches into the iv
// table for the mask or the flag, because they are not there.
bool watcher_p(mrb_state* mrb, mrb_value v) {
  return mrb_data_p(v) && DATA_TYPE(v) == &watcher_type;
}

unsigned watcher_events_mask(mrb_value v) {
  return static_cast<const WatcherData*>(DATA_PTR(v))->events;
}

bool watcher_aborted_p(mrb_value v) {
  return static_cast<const WatcherData*>(DATA_PTR(v))->aborted;
}

int watcher_fd(mrb_value v) {
  const auto* d = static_cast<const WatcherData*>(DATA_PTR(v));
  return d != nullptr ? d->fd : -1;
}

int watcher_slot(mrb_value v) {
  const auto* d = static_cast<const WatcherData*>(DATA_PTR(v));
  return d != nullptr ? d->slot : -1;
}

void watcher_set_slot(mrb_value v, int slot) {
  static_cast<WatcherData*>(DATA_PTR(v))->slot = slot;
}

// Armed: remember the ring, so the destructor can cancel on its own if
// it ever has to.
void watcher_armed(mrb_value v, struct io_uring* ring) {
  auto* d = static_cast<WatcherData*>(DATA_PTR(v));
  d->ring = ring;
  d->armed = true;
}

// THE NORMAL WAY OUT, and the connection's job. Cancelling belongs to
// the caller - it holds the ring and knows the round it is in - and this
// only empties the object afterwards: the data is freed and both the
// pointer and the type are cleared, so the sweep that comes later finds
// nothing to free and nothing to cancel a second time.
void watcher_disarm(mrb_value v) {
  auto* d = static_cast<WatcherData*>(DATA_PTR(v));
  if (d == nullptr) return;
  delete d;
  DATA_PTR(v) = nullptr;
  DATA_TYPE(v) = nullptr;
}

mrb_value watcher_source_of(mrb_state* mrb, mrb_value v) {
  return mrb_iv_get(mrb, v, MRB_IVSYM(source));
}

mrb_value watcher_block_of(mrb_state* mrb, mrb_value v) {
  return mrb_iv_get(mrb, v, MRB_IVSYM(block));
}

void watcher_init_class(mrb_state* mrb, struct RClass* wm) {
  struct RClass* c = mrb_define_class_under_id(mrb, wm, MRB_SYM(Watcher), mrb->object_class);
  MRB_SET_INSTANCE_TT(c, MRB_TT_CDATA);
  mrb_define_method_id(mrb, c, MRB_SYM(initialize), watcher_init, MRB_ARGS_ARG(1, 1) | MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, c, MRB_SYM(source), watcher_source, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM(block), watcher_block, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM(events), watcher_events, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM_E(events), watcher_events_set, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, c, MRB_SYM(abort), watcher_abort, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM_Q(aborted), watcher_aborted, MRB_ARGS_NONE());
}

}  // namespace webmachine
