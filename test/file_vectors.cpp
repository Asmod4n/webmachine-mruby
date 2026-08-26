/*
 * Test-only surface over the response.file step machine, compiled into
 * mrbtest and nothing else. Same shape as test/flow_vectors.cpp: it drives
 * the header from outside, and src/ carries no test code.
 *
 * What it proves is what used to need a server, a docroot, a socket and a
 * client - and, for the sizes past 2 GiB, an actual 3 GiB file on disk:
 *
 *   - every byte of a transfer goes out exactly once, in order;
 *   - no single lend exceeds kFileSendChunk, whatever the file's size,
 *     because a bigger one comes back short from the kernel and reads
 *     like a dead peer (MAX_RW_COUNT);
 *   - a mapping is NEVER handed back in a round that lends from it. That
 *     was a real bug: the release ran first, `map` was null by the time
 *     the plan was built, and the send walked the window buffer for the
 *     file's full length. Here it is one assertion;
 *   - the access line is owed exactly once per transfer, not once per
 *     window. That one was live too - 16 lines for one request;
 *   - the head rides exactly one round.
 *
 * Http1::file_step is pure, so none of this needs bytes: the mapping's
 * base is a number that is never dereferenced, and a 5 GiB transfer costs
 * a few hundred iterations.
 *
 *   FileVectors.walk(total, mapped, window)
 *     -> [rounds, bytes, max_chunk, contiguous, logs, releases,
 *         release_with_body, heads]
 */
#include <mruby.h>
#include <mruby/array.h>

#include "../src/webmachine.hpp"

namespace {

using webmachine::FileStage;
using webmachine::FileStep;
using webmachine::Http1;

// Never dereferenced - file_step only ever offsets it.
const char* const kBase = reinterpret_cast<const char*>(4096);

mrb_value walk(mrb_state* mrb, mrb_value)
{
  mrb_int total = 0, mapped = 0, window = 0;
  mrb_get_args(mrb, "iii", &total, &mapped, &window);
  if (total < 0 || window <= 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "total >= 0, window > 0");

  Http1::Conn::FileXfer x;
  x.total = static_cast<size_t>(total);
  x.sent = 0;
  x.persist = true;
  x.head.assign("HTTP/1.1 200 OK\r\n\r\n");
  const size_t win = static_cast<size_t>(window);
  if (mapped != 0) {
    x.map = kBase;
    x.map_len = x.total;
    x.len = x.total;
  } else {
    x.len = x.total < win ? x.total : win;
  }
  x.stage = FileStage::kDeliver;

  size_t rounds = 0, bytes = 0, maxchunk = 0, logs = 0, releases = 0, heads = 0;
  size_t expect_off = 0;
  bool contiguous = true, release_with_body = false;
  while (x.stage != FileStage::kNone) {
    if (++rounds > 1000000) mrb_raise(mrb, E_RUNTIME_ERROR, "step machine does not terminate");
    const FileStep s = Http1::file_step(x);
    if (s.head) heads++;
    if (s.log) logs++;
    if (s.release_map) {
      releases++;
      if (s.body != nullptr) release_with_body = true;
    }
    if (s.body != nullptr) {
      if (mapped != 0 && static_cast<size_t>(s.body - kBase) != expect_off) contiguous = false;
      bytes += s.body_len;
      if (s.body_len > maxchunk) maxchunk = s.body_len;
      expect_off += s.body_len;
    }
    // What file_apply does, minus the Conn it would need.
    x.sent = s.sent_after;
    x.stage = s.next;
    if (s.head) x.head.clear();
    if (s.release_map) {
      x.map = nullptr;
      x.map_len = 0;
    }
    // And what the Ring does: refill the window the read owes.
    if (x.stage == FileStage::kRing) {
      const size_t left = x.total - x.sent;
      x.len = left < win ? left : win;
      x.stage = FileStage::kDeliver;
    }
  }

  mrb_value out = mrb_ary_new_capa(mrb, 8);
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(rounds)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(bytes)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(maxchunk)));
  mrb_ary_push(mrb, out, mrb_bool_value(contiguous));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(logs)));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(releases)));
  mrb_ary_push(mrb, out, mrb_bool_value(release_with_body));
  mrb_ary_push(mrb, out, mrb_int_value(mrb, static_cast<mrb_int>(heads)));
  return out;
}

}  // namespace

extern "C" void
mrb_webmachine_file_vectors_init(mrb_state* mrb)
{
  struct RClass* m = mrb_define_module(mrb, "FileVectors");
  mrb_define_module_function(mrb, m, "walk", walk, MRB_ARGS_REQ(3));
  mrb_define_const(mrb, m, "SEND_CHUNK",
                   mrb_int_value(mrb, static_cast<mrb_int>(webmachine::kFileSendChunk)));
  mrb_define_const(mrb, m, "WINDOW",
                   mrb_int_value(mrb, static_cast<mrb_int>(webmachine::kResponseFileWindow)));
}
