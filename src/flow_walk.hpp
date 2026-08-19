// The tier-0 walker: the graph, run with the request's facts and a
// resource's konst answers - ZERO VM entries. A konst vector is
// compiled per resource class AND per method (B12/B10 fold the method
// into the answer at compile time, so the request never re-compares
// method strings at decision points). A node whose answer is not konst
// cannot be walked here; that caller pays tier 1 - one budgeted VM
// entry (95/191ns cached-sym, measured) - when the mruby integration
// lands.
#ifndef WEBMACHINE_FLOW_WALK_HPP
#define WEBMACHINE_FLOW_WALK_HPP

#include "flow.hpp"

namespace webmachine::flow {

enum class Method : uint8_t { kGet, kHead, kPost, kPut, kDelete, kOptions, kOther };

// What the kRequest nodes read: bits the framer already knows after
// phr, plus the two machine-state bits the tail nodes consult.
struct ReqFacts {
  Method method = Method::kGet;
  bool has_content_md5 = false;
  bool has_accept = false;
  bool has_accept_language = false;
  bool has_accept_charset = false;
  bool has_accept_encoding = false;
  bool has_if_match = false;
  bool if_match_star = false;
  bool has_if_unmodified_since = false;
  bool ius_valid = false;
  bool has_if_none_match = false;
  bool inm_star = false;
  bool has_if_modified_since = false;
  bool ims_valid = false;
  bool ims_future = false;
  bool response_has_location = false;
  bool response_has_body = true;
};

// One konst answer per node, resolved per resource class x method.
struct KonstAnswers {
  bool ans[kNodeCount] = {};
};

constexpr bool eval_request(Node id, const ReqFacts& r) {
  switch (id) {
    case Node::kB9: return r.has_content_md5;
    case Node::kB3: return r.method == Method::kOptions;
    case Node::kC3: return r.has_accept;
    case Node::kD4: return r.has_accept_language;
    case Node::kE5: return r.has_accept_charset;
    case Node::kF6: return r.has_accept_encoding;
    case Node::kG8: return r.has_if_match;
    case Node::kG9: return r.if_match_star;
    case Node::kH7: return r.has_if_match && r.if_match_star;
    case Node::kH10: return r.has_if_unmodified_since;
    case Node::kH11: return r.ius_valid;
    case Node::kI7: return r.method == Method::kPut;
    case Node::kI12: return r.has_if_none_match;
    case Node::kI13: return r.inm_star;
    case Node::kJ18: return r.method == Method::kGet || r.method == Method::kHead;
    case Node::kL7: return r.method == Method::kPost;
    case Node::kL13: return r.has_if_modified_since;
    case Node::kL14: return r.ims_valid;
    case Node::kL15: return r.ims_future;
    case Node::kM5: return r.method == Method::kPost;
    case Node::kM16: return r.method == Method::kDelete;
    case Node::kN16: return r.method == Method::kPost;
    case Node::kO16: return r.method == Method::kPut;
    case Node::kO20: return r.response_has_body;
    case Node::kP11: return r.response_has_location;
    default: return false;  // non-request nodes never arrive here
  }
}

constexpr uint16_t walk(const ReqFacts& req, const KonstAnswers& k) {
  Node n = Node::kB13;
  for (;;) {  // terminates: proven acyclic in flow.hpp
    const FlowNode& f = kFlow[static_cast<size_t>(n)];
    const bool ans =
        f.kind == Kind::kRequest ? eval_request(n, req) : k.ans[static_cast<size_t>(n)];
    const Target& t = ans ? f.on_true : f.on_false;
    if (t.status != 0) return t.status;
    n = t.node;
  }
}

// The compiled walk: the konst vector is a template parameter, so the
// compiler folds every konst node away at build time - what remains of
// the whole graph is a straight chain of request-fact tests. Measured
// against the interpreted walk above; the loser goes (Gebot 10).
namespace detail {
template <KonstAnswers K, Node N>
constexpr uint16_t step(const ReqFacts& req) {
  constexpr FlowNode f = kFlow[static_cast<size_t>(N)];
  if constexpr (f.kind != Kind::kRequest) {
    constexpr Target t = K.ans[static_cast<size_t>(N)] ? f.on_true : f.on_false;
    if constexpr (t.status != 0) return t.status;
    else return step<K, t.node>(req);
  } else {
    if (eval_request(N, req)) {  // N is constant: the switch folds to one test
      if constexpr (f.on_true.status != 0) return f.on_true.status;
      else return step<K, f.on_true.node>(req);
    } else {
      if constexpr (f.on_false.status != 0) return f.on_false.status;
      else return step<K, f.on_false.node>(req);
    }
  }
}
}  // namespace detail

template <KonstAnswers K>
constexpr uint16_t walk_compiled(const ReqFacts& req) {
  return detail::step<K, Node::kB13>(req);
}

// The bitset walk: every answer is one bit (57 nodes fit a word), so a
// RUNTIME-defined resource - the Ruby case, where the konst vector is
// data, not a template parameter - still walks without a single switch:
// request bits are built branchless once per request and merged over
// the resource's konst bits by mask.
static_assert(kNodeCount <= 64, "answers must fit one word");

constexpr uint64_t bit(Node n) { return uint64_t{1} << static_cast<size_t>(n); }

constexpr uint64_t request_mask() {
  uint64_t m = 0;
  for (size_t i = 0; i < kNodeCount; i++) {
    if (kFlow[i].kind == Kind::kRequest) m |= uint64_t{1} << i;
  }
  return m;
}
inline constexpr uint64_t kRequestMask = request_mask();

constexpr uint64_t konst_bits(const KonstAnswers& k) {
  uint64_t b = 0;
  for (size_t i = 0; i < kNodeCount; i++) {
    if (k.ans[i]) b |= uint64_t{1} << i;
  }
  return b;
}

constexpr uint64_t request_bits(const ReqFacts& r) {
  uint64_t b = 0;
  b |= uint64_t{r.has_content_md5} << static_cast<size_t>(Node::kB9);
  b |= uint64_t{r.method == Method::kOptions} << static_cast<size_t>(Node::kB3);
  b |= uint64_t{r.has_accept} << static_cast<size_t>(Node::kC3);
  b |= uint64_t{r.has_accept_language} << static_cast<size_t>(Node::kD4);
  b |= uint64_t{r.has_accept_charset} << static_cast<size_t>(Node::kE5);
  b |= uint64_t{r.has_accept_encoding} << static_cast<size_t>(Node::kF6);
  b |= uint64_t{r.has_if_match} << static_cast<size_t>(Node::kG8);
  b |= uint64_t{r.if_match_star} << static_cast<size_t>(Node::kG9);
  b |= uint64_t{r.has_if_match && r.if_match_star} << static_cast<size_t>(Node::kH7);
  b |= uint64_t{r.has_if_unmodified_since} << static_cast<size_t>(Node::kH10);
  b |= uint64_t{r.ius_valid} << static_cast<size_t>(Node::kH11);
  b |= uint64_t{r.method == Method::kPut} << static_cast<size_t>(Node::kI7);
  b |= uint64_t{r.has_if_none_match} << static_cast<size_t>(Node::kI12);
  b |= uint64_t{r.inm_star} << static_cast<size_t>(Node::kI13);
  b |= uint64_t{r.method == Method::kGet || r.method == Method::kHead}
       << static_cast<size_t>(Node::kJ18);
  b |= uint64_t{r.method == Method::kPost} << static_cast<size_t>(Node::kL7);
  b |= uint64_t{r.has_if_modified_since} << static_cast<size_t>(Node::kL13);
  b |= uint64_t{r.ims_valid} << static_cast<size_t>(Node::kL14);
  b |= uint64_t{r.ims_future} << static_cast<size_t>(Node::kL15);
  b |= uint64_t{r.method == Method::kPost} << static_cast<size_t>(Node::kM5);
  b |= uint64_t{r.method == Method::kDelete} << static_cast<size_t>(Node::kM16);
  b |= uint64_t{r.method == Method::kPost} << static_cast<size_t>(Node::kN16);
  b |= uint64_t{r.method == Method::kPut} << static_cast<size_t>(Node::kO16);
  b |= uint64_t{r.response_has_body} << static_cast<size_t>(Node::kO20);
  b |= uint64_t{r.response_has_location} << static_cast<size_t>(Node::kP11);
  return b;
}

constexpr uint64_t merge(uint64_t req_bits, uint64_t konst) {
  return (req_bits & kRequestMask) | (konst & ~kRequestMask);
}

constexpr uint16_t walk_bits(uint64_t answers) {
  Node n = Node::kB13;
  for (;;) {  // terminates: proven acyclic in flow.hpp
    const FlowNode& f = kFlow[static_cast<size_t>(n)];
    const Target& t = ((answers >> static_cast<size_t>(n)) & 1) != 0 ? f.on_true : f.on_false;
    if (t.status != 0) return t.status;
    n = t.node;
  }
}

// webmachine-ruby's Resource defaults, folded per method - the konst
// vector a resource that overrides nothing compiles to. allowed_methods
// defaults to GET/HEAD there, so every other method konsts into 405 at
// B10 before anything else runs.
constexpr KonstAnswers default_konst(Method m) {
  KonstAnswers k{};
  const auto set = [&](Node n, bool v) { k.ans[static_cast<size_t>(n)] = v; };
  set(Node::kB13, true);   // service_available? -> true
  set(Node::kB12, true);   // known_methods covers the standard set
  set(Node::kB11, false);  // uri_too_long? -> false
  set(Node::kB10, m == Method::kGet || m == Method::kHead);  // allowed_methods
  set(Node::kB9a, true);   // validate_content_checksum -> valid
  set(Node::kB9b, false);  // malformed_request? -> false
  set(Node::kB8, true);    // is_authorized? -> true
  set(Node::kB7, false);   // forbidden? -> false
  set(Node::kB6, true);    // valid_content_headers? -> true
  set(Node::kB5, true);    // known_content_type? -> true
  set(Node::kB4, true);    // valid_entity_length? -> true
  set(Node::kG7, true);    // resource_exists? -> true
  set(Node::kL17, true);   // last_modified nil reads as modified (flow.rb l17)
  set(Node::kM20b, true);  // delete_completed? -> true
  set(Node::kO18, true);   // body render passes through (both edges agree)
  set(Node::kO18b, false); // multiple_choices? -> false -> 200
  // moved_*/previously_existed?/conflict?/etag/post hooks default false.
  return k;
}

// The golden paths, proven when this header compiles - the walker and
// the table cannot drift from flow.rb's semantics without failing here.
namespace proof {
constexpr ReqFacts get_plain{};
static_assert(walk(get_plain, default_konst(Method::kGet)) == 200,
              "plain GET on the default resource is 200");
constexpr ReqFacts options{.method = Method::kOptions};
static_assert(walk(options, default_konst(Method::kOptions)) == 405,
              "OPTIONS not in default allowed_methods dies at B10 like anything else");
constexpr KonstAnswers options_allowed = [] {
  KonstAnswers k = default_konst(Method::kOptions);
  k.ans[static_cast<size_t>(Node::kB10)] = true;  // resource lists OPTIONS
  return k;
}();
static_assert(walk(options, options_allowed) == 200,
              "OPTIONS answers 200 from options() once allowed (B3)");
constexpr ReqFacts del{.method = Method::kDelete};
static_assert(walk(del, default_konst(Method::kDelete)) == 405,
              "default allowed_methods is GET/HEAD: DELETE is 405 at B10");
constexpr ReqFacts inm_star{.has_if_none_match = true, .inm_star = true};
static_assert(walk(inm_star, default_konst(Method::kGet)) == 304,
              "GET with If-None-Match: * on an existing resource is 304");
constexpr ReqFacts im_star_missing{.has_if_match = true, .if_match_star = true};
constexpr KonstAnswers missing = [] {
  KonstAnswers k = default_konst(Method::kGet);
  k.ans[static_cast<size_t>(Node::kG7)] = false;  // resource_exists? -> false
  return k;
}();
static_assert(walk(im_star_missing, missing) == 412,
              "If-Match: * against a missing resource is 412 (H7)");
static_assert(walk(get_plain, missing) == 404,
              "GET on a never-existed resource is 404 (L7)");
// The compiled walk must agree with the interpreted one everywhere the
// proofs reach.
static_assert(walk_compiled<default_konst(Method::kGet)>(get_plain) == 200);
static_assert(walk_compiled<default_konst(Method::kDelete)>(del) == 405);
static_assert(walk_compiled<default_konst(Method::kGet)>(inm_star) == 304);
static_assert(walk_compiled<missing>(im_star_missing) == 412);
static_assert(walk_compiled<missing>(get_plain) == 404);
// And so must the bitset walk, which serves runtime-defined resources.
constexpr uint16_t wb(const ReqFacts& r, const KonstAnswers& k) {
  return walk_bits(merge(request_bits(r), konst_bits(k)));
}
static_assert(wb(get_plain, default_konst(Method::kGet)) == 200);
static_assert(wb(del, default_konst(Method::kDelete)) == 405);
static_assert(wb(inm_star, default_konst(Method::kGet)) == 304);
static_assert(wb(im_star_missing, missing) == 412);
static_assert(wb(get_plain, missing) == 404);
}  // namespace proof

}  // namespace webmachine::flow

#endif
