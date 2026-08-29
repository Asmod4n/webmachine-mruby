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

// Nothing here is a Ruby object; `source` and `block` are, and live in
// the iv table. RData carries both (mruby/data.h).
struct WatcherData {
  // Taken once in initialize; the destructor cannot ask a sweeping GC
  // for it. int, not a handle type - Windows CRT hands out int fds too.
  int fd = -1;
  // #30: the key on Http1::Conn's hash, and bits 48..55 of the tag.
  int slot = -1;
  // POLLIN, POLLOUT or both.
  unsigned events = POLLIN;
  // Set by watcher.abort, read after the block returns.
  bool aborted = false;
  struct io_uring* ring = nullptr;
  bool armed = false;
};

// Reached only when nobody disarmed first - a raise out of a callback.
// Http1::Conn::watchers_drop empties the CDATA, so the usual sweep finds
// nothing here.
void watcher_free(mrb_state*, void* p) {
  auto* d = static_cast<WatcherData*>(p);
  if (d == nullptr) return;
  if (d->armed && d->ring != nullptr && d->fd >= 0) {
    struct io_uring_sqe* s = io_uring_get_sqe(d->ring);
    if (s != nullptr) {
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

// What may be ORDERED. What arrives (revents) is a wider set.
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

// Watcher.new(source, :r) { |revents, watcher| ... } - a description.
// Arming happens when a resource hands one back; see #30.
mrb_value watcher_init(mrb_state* mrb, mrb_value self) {
  mrb_value source;
  mrb_value events = mrb_symbol_value(MRB_SYM(r));
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "o|o&", &source, &events, &blk);

  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR,
              "a watcher without a block would have nothing to do when it fires");
  }

  // An Integer passes through; anything else is asked for fileno.
  // mruby-hiredis hands its event callbacks a bare int.
  const mrb_int fd = mrb_integer(mrb_type_convert(mrb, source, MRB_TT_INTEGER, MRB_SYM(fileno)));
  if (fd < 0) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "a watcher needs a descriptor, and this one is %i", fd);
  }

  auto* d = new WatcherData();
  d->fd = static_cast<int>(fd);
  d->events = mask_of(mrb, events);
  mrb_data_init(self, d, &watcher_type);

  // The only two the GC has to see.
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

// IORING_POLL_UPDATE_EVENTS on the armed poll; no re-registration.
mrb_value watcher_events_set(mrb_state* mrb, mrb_value self) {
  mrb_value v;
  mrb_get_args(mrb, "o", &v);
  live(mrb, self)->events = mask_of(mrb, v);
  return v;
}

mrb_value watcher_abort(mrb_state* mrb, mrb_value self) {
  live(mrb, self)->aborted = true;
  return self;
}

mrb_value watcher_aborted(mrb_state* mrb, mrb_value self) {
  return mrb_bool_value(live(mrb, self)->aborted);
}

}  // namespace

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

void watcher_armed(mrb_value v, struct io_uring* ring) {
  auto* d = static_cast<WatcherData*>(DATA_PTR(v));
  d->ring = ring;
  d->armed = true;
}

// Empties the CDATA after the caller has cancelled, so watcher_free
// finds nothing.
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
