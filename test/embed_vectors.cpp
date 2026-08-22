/*
 * Test-only surface over the embedder facade, compiled into mrbtest
 * and nothing else (mruby builds test/* of a gem only for its test
 * binary). src/ never carries test code; this drives the header from
 * outside, the way a real embedder does - which is the whole point of
 * src/embed.hpp existing.
 *
 * What it proves: a complete HTTP/1.1 exchange runs with no IO at all.
 * The request arrives as chunks the caller already holds, the response
 * leaves as a string, and this file has no socket, no descriptor and
 * no reactor - see the #error below, which is the cut stated as a
 * build failure rather than as a claim.
 *
 *   EmbedVectors.exchange([chunk, ...]) -> [response_bytes, still_open]
 */
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/string.h>

#include <string>

#include "embed.hpp"
#include "resource.hpp"
#include "router.hpp"

/* THE PROOF THE FACADE EXISTS FOR. embed.hpp is the machine without
 * the reactor; if the reactor ever comes back through it - directly or
 * through any header it reaches - this translation unit stops the
 * build instead of quietly linking a server into a test. ring.hpp is
 * the only thing in this tree that names <liburing.h>, and it announces
 * itself by its guard. mrbgem.rake makes the same check on the include
 * text, for the include liburing.h would arrive through. */
#ifdef WEBMACHINE_RING_HPP
#error "embed.hpp pulled in the reactor: the embedder facade must carry no IO (#173)"
#endif

namespace {

mrb_value exchange(mrb_state *mrb, mrb_value)
{
  mrb_value chunks;
  mrb_get_args(mrb, "A", &chunks);

  /* Fully konst: the default Resource is webmachine-ruby's unbound
   * one, so this exchange needs no VM tier and no assets - the flow
   * machine alone answers. ONE splat route, which is what an app
   * without routes of its own has meant since #116: every path lands
   * on the same resource. */
  webmachine::RouteTable table;
  table.open();
  table.splat();
  table.commit();
  webmachine::Resource unbound;
  const webmachine::Resource *rp = &unbound;
  webmachine::Http1 app(table, &rp, 1);
  webmachine::Embedded conn(app);

  std::string out;
  bool open = true;
  for (mrb_int i = 0; i < RARRAY_LEN(chunks); i++) {
    const mrb_value c = mrb_ary_entry(chunks, i);
    if (!mrb_string_p(c)) mrb_raise(mrb, E_TYPE_ERROR, "chunks must be strings");
    open = conn.feed(RSTRING_PTR(c), (size_t)RSTRING_LEN(c), out);
    if (!open) break;  /* the machine is done; further bytes are refused */
  }
  /* feed's post-condition: drain ran to the floor, so nothing is owed.
   * A facade that stopped short would leave the caller holding half a
   * response with no event left to deliver the rest. */
  if (conn.owes()) mrb_raise(mrb, E_RUNTIME_ERROR, "feed returned with bytes still owed");

  mrb_value res = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, res, mrb_str_new(mrb, out.data(), out.size()));
  mrb_ary_push(mrb, res, mrb_bool_value(open));
  return res;
}

}  // namespace

extern "C" void
mrb_webmachine_embed_vectors_init(mrb_state *mrb)
{
  struct RClass *m = mrb_define_module(mrb, "EmbedVectors");
  mrb_define_module_function(mrb, m, "exchange", exchange, MRB_ARGS_REQ(1));
  /* The date field the caller has to step over to compare bytes. */
  mrb_define_const(mrb, m, "DATE_LEN", mrb_int_value(mrb, 29));
}
