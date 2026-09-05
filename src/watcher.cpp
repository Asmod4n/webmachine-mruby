// Design decisions live in .DESIGN.md, filed under what each comment names.
#include <cstdio>

#include "webmachine.hpp"

#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/variable.h>
#include <mruby/string.h>

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
  // #30: how many seconds this watcher may stay quiet. A descriptor
  // that says nothing is the usual end of a wait, so a watcher owes a
  // deadline the same way a compute task owes max_runtime. What the two
  // do at the deadline differs, and only that.
  double timeout = 0.0;
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

// Watcher.new(source, :r, timeout: 5.0) { |revents, watcher| ... } - a
// description. Arming happens when a resource hands one back; see #30.
mrb_value watcher_init(mrb_state* mrb, mrb_value self) {
  mrb_value source;
  mrb_value events = mrb_symbol_value(MRB_SYM(r));
  mrb_value blk = mrb_nil_value();
  // mruby checks keywords against a DECLARED table. timeout is declared
  // optional, so the refusal below is ours and says why a deadline is
  // owed. The slot starts as undef, because mrb_get_args leaves a key
  // that was not given untouched.
  const mrb_sym kw_names[] = {MRB_SYM(timeout)};
  mrb_value kw_values[1] = {mrb_undef_value()};
  const mrb_kwargs kwargs = {1, 0, kw_names, kw_values, nullptr};
  mrb_get_args(mrb, "o|o:&", &source, &events, &kwargs, &blk);

  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR,
              "a watcher without a block would have nothing to do when it fires");
  }

  const mrb_value wait = mrb_undef_p(kw_values[0]) ? mrb_nil_value() : kw_values[0];
  if (mrb_nil_p(wait)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR,
              "a watcher wants timeout: - without a deadline it waits for a wakeup that "
              "can stop coming, and the run waits with it");
  }
  const mrb_float secs = mrb_as_float(mrb, wait);
  if (!(secs > 0.0)) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "timeout: %v is not a time a watcher could wait", wait);
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
  d->timeout = static_cast<double>(secs);
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

mrb_value watcher_timeout_m(mrb_state* mrb, mrb_value self) {
  return mrb_float_value(mrb, live(mrb, self)->timeout);
}

// #30: the peer said nothing for `timeout` seconds. That is the world
// and not a fault of the application, so it arrives at the block as an
// event, exactly as a readable descriptor does. `:timeout` is a value
// that ARRIVES and cannot be ordered, which is why revents and events
// do not share a menu.
//
// The block answers with what it does: it calls abort to give up, or it
// returns and waits again. The reactor reads that answer here.
mrb_value watcher_deadline_passed_m(mrb_state* mrb, mrb_value self) {
  live(mrb, self);
  const mrb_value blk = mrb_iv_get(mrb, self, MRB_IVSYM(block));
  const mrb_value argv[2] = {mrb_symbol_value(MRB_SYM(timeout)), self};
  mrb_yield_argv(mrb, blk, 2, argv);
  // The block can abort, and abort frees nothing - the CDATA is still
  // here, so it is read after the call and not before.
  return mrb_bool_value(!live(mrb, self)->aborted);
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

double watcher_timeout(mrb_value v) {
  const auto* d = static_cast<const WatcherData*>(DATA_PTR(v));
  return d != nullptr ? d->timeout : 0.0;
}

// The deadline, delivered. The answer says whether the wait goes on;
// `said` takes the block's own value, which is the run's answer when the
// block ends the wait here - a watcher that gives up still has something
// to say, and dropping it would make a timeout answer nil forever.
bool watcher_deadline_passed(mrb_state* mrb, mrb_value v, mrb_value* said) {
  const mrb_value blk = mrb_iv_get(mrb, v, MRB_IVSYM(block));
  const mrb_value argv[2] = {mrb_symbol_value(MRB_SYM(timeout)), v};
  const mrb_value answer = mrb_yield_argv(mrb, blk, 2, argv);
  if (said != nullptr) *said = answer;
  // The block can abort, and abort frees nothing - the CDATA is still
  // here, so it is read after the call and not before.
  return !live(mrb, v)->aborted;
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
  mrb_define_method_id(mrb, c, MRB_SYM(initialize), watcher_init,
                       MRB_ARGS_ARG(1, 1) | MRB_ARGS_KEY(1, 0) | MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, c, MRB_SYM(source), watcher_source, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM(block), watcher_block, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM(events), watcher_events, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM_E(events), watcher_events_set, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, c, MRB_SYM(abort), watcher_abort, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM_Q(aborted), watcher_aborted, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM(timeout), watcher_timeout_m, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, c, MRB_SYM(deadline_passed), watcher_deadline_passed_m,
                       MRB_ARGS_NONE());
}

}  // namespace webmachine

// #30: the reactor's half. Everything above describes a watcher; this
// is what the server does with one, and it runs on the reactor's thread
// with the reactor's VM - the same rule the compute task follows.
namespace webmachine {

// The watcher a stopped run left, filed under a slot on the connection.
// The connection's hash is what roots it: the run's own frame is gone
// one line later, and a watcher nobody holds is collected while the
// descriptor is still in the ring.
bool Http1::watch_hand_over(Conn& st, const Resource& res) {
  if (!res.run.watch_held) return false;
  const int slot = st.watchers_add(res.mrb, res.run.watch);
  if (slot < 0) return false;
  st.w_slot = slot;
  return true;
}

int Http1::watcher_descriptor(Conn& st, int slot) {
  const mrb_value w = st.watchers_at(slot);
  return mrb_nil_p(w) ? -1 : watcher_fd(w);
}

void Http1::watcher_is_armed(Conn& st, int slot, struct io_uring* ring) {
  const mrb_value w = st.watchers_at(slot);
  if (!mrb_nil_p(w)) watcher_armed(w, ring);
}

// The wait is over, however it ended. The watcher goes, and with it the
// descriptor's place in the ring.
void Http1::watchers_drop_slot(Conn& st, int slot) {
  st.watchers_drop(slot);
  if (st.w_slot == slot) st.w_slot = -1;
}

unsigned Http1::watcher_mask(Conn& st, int slot) {
  const mrb_value w = st.watchers_at(slot);
  if (mrb_nil_p(w)) return 0;
  return watcher_events_mask(w);
}

double Http1::watcher_quiet_seconds(Conn& st, int slot) {
  const mrb_value w = st.watchers_at(slot);
  if (mrb_nil_p(w)) return 0.0;
  return watcher_timeout(w);
}

Http1::WatchStep Http1::watcher_event(Conn& st, int slot, unsigned revents) {
  const mrb_value w = st.watchers_at(slot);
  if (mrb_nil_p(w)) return WatchStep::kDone;
  mrb_state* const mrb = st.w_mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const unsigned before = watcher_events_mask(w);
  const mrb_value block = watcher_block_of(mrb, w);
  const mrb_value argv[2] = {sym_of(mrb, revents), w};
  const mrb_value said = mrb_funcall_argv(mrb, block, MRB_SYM(call), 2, argv);
  if (mrb->exc != nullptr) {
    // A raise inside the block ends the wait. The run reads nil and
    // answers 500 the way it answers any raise.
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    st.answer_value[0] = mrb_nil_value();
    st.answer_ready = true;
    return WatchStep::kDone;
  }
  if (watcher_aborted_p(w)) {
    // ROOT IT FIRST. The block's answer is held by the arena and by
    // nothing else; restoring the arena before registering it hands the
    // collector a value the run is about to read.
    st.answer_value[0] = said;
    mrb_gc_register(mrb, st.answer_value[0]);
    mrb_gc_arena_restore(mrb, ai);
    st.answer_ready = true;
    return WatchStep::kDone;
  }
  mrb_gc_arena_restore(mrb, ai);
  return watcher_events_mask(w) != before ? WatchStep::kRearm : WatchStep::kWait;
}

Http1::WatchStep Http1::watcher_deadline(Conn& st, int slot) {
  const mrb_value w = st.watchers_at(slot);
  if (mrb_nil_p(w)) return WatchStep::kDone;
  mrb_state* const mrb = st.w_mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const unsigned before = watcher_events_mask(w);
  // The block hears :timeout and answers whether the wait goes on. A
  // watcher over its deadline is usually the WORLD - the peer said
  // nothing - and that is a fact the application has to learn, not a
  // failure of its own (.DESIGN.md #promise-bound).
  mrb_value said = mrb_nil_value();
  const bool again = watcher_deadline_passed(mrb, w, &said);
  if (mrb->exc != nullptr) {
    mrb->exc = nullptr;
    said = mrb_nil_value();
  }
  if (!again) {
    st.answer_value[0] = said;
    mrb_gc_register(mrb, st.answer_value[0]);
    mrb_gc_arena_restore(mrb, ai);
    st.answer_ready = true;
    return WatchStep::kDone;
  }
  mrb_gc_arena_restore(mrb, ai);
  return watcher_events_mask(w) != before ? WatchStep::kRearm : WatchStep::kWait;
}

}  // namespace webmachine
