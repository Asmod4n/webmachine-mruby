/*
 * Test-only surface over the flow walker, compiled into mrbtest and
 * nothing else (mruby builds test/* of a gem only for its test
 * binary). src/ never carries test code; this drives the header from
 * outside, the way test/hpack_vectors.c drives the codec.
 *
 * What it proves: flow::answer - the shortcut that lets a request skip
 * the graph - can never disagree with flow::walk, the graph itself.
 *
 * The shortcut has two branches, and only one of them needs proving:
 *
 *   req.plain  -> by construction. `plain` asserts every non-method
 *                 fact is at its default, and shortcut.status IS
 *                 walk(default facts, k). Same input, same walk.
 *   s.always   -> a CLAIM, made by any_request_node: that no reachable
 *                 node reads the request, so the facts cannot matter.
 *                 If that claim is ever wrong, a request gets an answer
 *                 the graph would not have given. That is what the
 *                 sweep below hunts, by brute force.
 *
 * So the sweep varies every fact walk can read, over konst vectors it
 * generates at random - vectors no resource would compile to, which is
 * the point: the claim must hold for the graph, not for the plausible
 * corner of it. `plain` is computed here from the mask rather than
 * taken on trust, because a caller that lies about it is a bug in the
 * caller (http::header_switch), not in the shortcut.
 *
 *   FlowVectors.sweep(seed, n_random) -> comparisons made
 *   FlowVectors.default_shortcut(method) -> [status, always]
 */
#include <mruby.h>
#include <mruby/array.h>

#include "../src/webmachine.hpp"


namespace {

using webmachine::flow::KonstAnswers;
using webmachine::flow::Method;
using webmachine::flow::ReqFacts;
using webmachine::flow::Shortcut;

/* Every field walk reads apart from the method. A set bit means the
 * field DIFFERS from its default - which is why response_has_body,
 * whose default is true, is inverted here: mask 0 must mean "the facts
 * a plain request carries", or `plain` would be a different claim than
 * the one flow::answer makes. */
enum { kFactBits = 16 };

ReqFacts facts_of(Method m, uint32_t mask)
{
  ReqFacts r;
  r.method = m;
  r.has_content_md5         = (mask & (1u << 0))  != 0;
  r.has_accept              = (mask & (1u << 1))  != 0;
  r.has_accept_language     = (mask & (1u << 2))  != 0;
  r.has_accept_charset      = (mask & (1u << 3))  != 0;
  r.has_accept_encoding     = (mask & (1u << 4))  != 0;
  r.has_if_match            = (mask & (1u << 5))  != 0;
  r.if_match_star           = (mask & (1u << 6))  != 0;
  r.has_if_unmodified_since = (mask & (1u << 7))  != 0;
  r.if_unmodified_since_valid               = (mask & (1u << 8))  != 0;
  r.has_if_none_match       = (mask & (1u << 9))  != 0;
  r.if_none_match_star                = (mask & (1u << 10)) != 0;
  r.has_if_modified_since   = (mask & (1u << 11)) != 0;
  r.if_modified_since_valid               = (mask & (1u << 12)) != 0;
  r.if_modified_since_future              = (mask & (1u << 13)) != 0;
  r.response_has_location   = (mask & (1u << 14)) != 0;
  r.response_has_body       = (mask & (1u << 15)) == 0;
  r.plain = mask == 0;
  return r;
}

/* splitmix64: a few lines, no library, same stream on every host - a
 * seed in the test file is a reproducible failure, not a lottery. */
uint64_t mix(uint64_t *s)
{
  uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

/* Sweeps one konst vector: every method against every fact mask. */
mrb_int sweep_konst(mrb_state *mrb, const KonstAnswers &k, const char *what, uint64_t id)
{
  mrb_int n = 0;
  for (uint8_t m = 0; m < 7; m++) {
    const Method meth = static_cast<Method>(m);
    const Shortcut s = webmachine::flow::shortcut_for(meth, k);
    for (uint32_t mask = 0; mask < (1u << kFactBits); mask++) {
      const ReqFacts r = facts_of(meth, mask);
      const uint16_t shortcut = webmachine::flow::answer(r, k, s);
      const uint16_t graph = webmachine::flow::walk(r, k);
      if (shortcut != graph) {
        mrb_raisef(mrb, E_RUNTIME_ERROR,
                   "%s vector %d method %d mask %d: shortcut said %d, graph said %d",
                   what, (mrb_int)id, (mrb_int)m, (mrb_int)mask, (mrb_int)shortcut,
                   (mrb_int)graph);
      }
      n++;
    }
  }
  return n;
}

mrb_value sweep(mrb_state *mrb, mrb_value)
{
  mrb_int seed = 0, n_random = 0;
  mrb_get_args(mrb, "ii", &seed, &n_random);
  if (n_random < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "n_random must not be negative");

  /* The vector every resource that overrides nothing compiles to. */
  mrb_int n = 0;
  for (uint8_t m = 0; m < 7; m++) {
    n += sweep_konst(mrb, webmachine::flow::default_konst(static_cast<Method>(m)), "default", m);
  }

  uint64_t st = (uint64_t)seed;
  for (mrb_int v = 0; v < n_random; v++) {
    KonstAnswers k{};
    for (size_t i = 0; i < webmachine::flow::kNodeCount; i++) k.ans[i] = (mix(&st) & 1) != 0;
    n += sweep_konst(mrb, k, "random", (uint64_t)v);
  }
  return mrb_int_value(mrb, n);
}

mrb_value default_shortcut(mrb_state *mrb, mrb_value)
{
  mrb_int m = 0;
  mrb_get_args(mrb, "i", &m);
  if (m < 0 || m > 6) mrb_raise(mrb, E_ARGUMENT_ERROR, "method index out of range");
  const Method meth = static_cast<Method>(m);
  const Shortcut s = webmachine::flow::shortcut_for(meth, webmachine::flow::default_konst(meth));
  mrb_value out = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, out, mrb_int_value(mrb, s.status));
  mrb_ary_push(mrb, out, mrb_bool_value(s.always));
  return out;
}

}  // namespace

extern "C" void
mrb_webmachine_flow_vectors_init(mrb_state *mrb)
{
  struct RClass *m = mrb_define_module(mrb, "FlowVectors");
  mrb_define_module_function(mrb, m, "sweep", sweep, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, m, "default_shortcut", default_shortcut, MRB_ARGS_REQ(1));
  mrb_define_const(mrb, m, "FACT_BITS", mrb_int_value(mrb, kFactBits));
}
