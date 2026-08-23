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

#include <string>

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
  // True while every header-derived fact above is still false - the
  // request carried no conditional and no conneg field. Cleared by
  // http::header_switch, the one place those facts are born, which h1
  // and h2 already share. It is what lets `answer` skip the graph:
  // with nothing set, the outcome was decided at add_route.
  bool plain = true;
  // NOT a flow fact - no node reads it and it never clears `plain`.
  // The peer said "do not track" (DNT: 1 / Sec-GPC: 1); the access
  // log caps this request's %h at anon. It lives here because facts
  // is the one struct that survives h2's stream parking, and the log
  // line is written when the parked stream finally answers.
  bool no_track = false;
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

// Run only what cannot be predicted; have the rest as a result.
//
// A konst vector decides most of the graph at add_route, and the
// method is folded into it - so of the 58 nodes, a default resource
// visits 46 for GET (21 of them request-dependent) and just 4 for
// POST/PUT/DELETE/OPTIONS, where NOTHING depends on the request: four
// node visits per request to rediscover a fixed 405. Two values,
// computed once per resource x method, retire both cases.
struct Shortcut {
  uint16_t status = 0;  // the answer when there is nothing to decide
  bool always = false;  // no request-dependent node reachable at all
};

// Does any reachable node read the request? Explores BOTH branches at
// a kRequest node (either may be taken at runtime) and follows the
// konst answer everywhere else. Terminates for the same reason walk
// does - the graph is proven acyclic in flow.hpp - and `seen` bounds
// it regardless.
constexpr bool any_request_node(Node n, const KonstAnswers& k, bool* seen) {
  if (seen[static_cast<size_t>(n)]) return false;
  seen[static_cast<size_t>(n)] = true;
  const FlowNode& f = kFlow[static_cast<size_t>(n)];
  if (f.kind == Kind::kRequest) return true;
  const Target& t = k.ans[static_cast<size_t>(n)] ? f.on_true : f.on_false;
  if (t.status != 0) return false;
  return any_request_node(t.node, k, seen);
}

// Built at add_route, never per request. `status` comes from the SAME
// walk the request path uses, run once with every header fact false -
// no second interpreter to drift from the first.
constexpr Shortcut shortcut_for(Method m, const KonstAnswers& k) {
  Shortcut s;
  ReqFacts plain_facts;
  plain_facts.method = m;
  s.status = walk(plain_facts, k);
  bool seen[kNodeCount] = {};
  s.always = !any_request_node(Node::kB13, k, seen);
  return s;
}

// The one entry point the request path calls. Two integer tests stand
// in for the graph whenever the graph could not have said anything
// else; everything conditional still walks it, so the answers cannot
// differ - test/flow.rb proves that exhaustively.
constexpr uint16_t answer(const ReqFacts& req, const KonstAnswers& k, const Shortcut& s) {
  if (s.always || req.plain) return s.status;
  return walk(req, k);
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

// A bitset walk (all answers one word, branchless request bits, no
// switch) was measured and REMOVED: it lost to the plain interpreted
// walk on both machines (forgecore 37.2 vs 34.0ns, Pi 87.7 vs 81.9ns) -
// the branchless bit build cost more than the predicted switch saved.
// History holds the code; the numbers hold the verdict. Open question
// attached to the grave: on a noisy shared vCPU it led (container 60
// vs 70ns), so IF a cloud instance ever becomes a measured target,
// resurrect and re-measure THERE - never resurrect on this evidence
// alone. Note the path branches (edge per node) are identical in both;
// only the dispatch differed.

// webmachine-ruby's Resource defaults, folded per method - the konst
// vector a resource that overrides nothing compiles to. allowed_methods
// defaults to GET/HEAD there, so every other method konsts into 405 at
// B10 before anything else runs.
constexpr KonstAnswers default_konst(Method m) {
  KonstAnswers k{};
  const auto set = [&](Node n, bool v) { k.ans[static_cast<size_t>(n)] = v; };
  set(Node::kB13, true);   // service_available? -> true
  set(Node::kB12, m != Method::kOther);  // known_methods covers the standard set
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
  // The default resource's provided lists negotiate every request;
  // value-dependent conneg (a narrow Accept against a narrow list) is
  // a later tier, not a konst bit.
  set(Node::kC4, true);
  set(Node::kD5, true);
  set(Node::kE6, true);
  set(Node::kF7, true);
  set(Node::kL17, true);   // last_modified nil reads as modified (flow.rb l17)
  set(Node::kM20b, true);  // delete_completed? -> true
  set(Node::kO18, true);   // body render passes through (both edges agree)
  set(Node::kO18b, false); // multiple_choices? -> false -> 200
  // moved_*/previously_existed?/conflict?/etag/post hooks default false.
  return k;
}

// Everything a resource compiles down to: one konst vector per method,
// the Allow line B10's 405 speaks, and the rendered representation
// (body + its content type). Defaults are webmachine-ruby's Resource
// defaults; resource_setup overwrites them from the app's subclass at
// setup - never per request.
struct KonstSet {
  KonstAnswers per_method[7];
  // Parallel to per_method: what the graph would have said when it had
  // nothing to decide. Whoever changes per_method must call
  // resolve_shortcuts() after - resource_setup does, and the ctor
  // below does for the defaults.
  Shortcut shortcut[7];
  std::string allow = "GET, HEAD";
  std::string body = "OK";
  std::string content_type;  // empty: no Content-Type header (the bare floor)
  KonstSet() {
    for (uint8_t m = 0; m < 7; m++) per_method[m] = default_konst(static_cast<Method>(m));
    resolve_shortcuts();
  }
  void resolve_shortcuts() {
    for (uint8_t m = 0; m < 7; m++) {
      shortcut[m] = shortcut_for(static_cast<Method>(m), per_method[m]);
    }
  }
};

// The golden paths, proven when this header compiles - the walker and
// the table cannot drift from flow.rb's semantics without failing here.
namespace proof {
constexpr ReqFacts get_plain{};
static_assert(walk(get_plain, default_konst(Method::kGet)) == 200,
              "plain GET on the default resource is 200");
constexpr ReqFacts get_negotiated{.has_accept = true,
                                  .has_accept_language = true,
                                  .has_accept_charset = true,
                                  .has_accept_encoding = true};
static_assert(walk(get_negotiated, default_konst(Method::kGet)) == 200,
              "a browser GET negotiates through C4/D5/E6/F7 to 200");
constexpr ReqFacts unknown{.method = Method::kOther};
static_assert(walk(unknown, default_konst(Method::kOther)) == 501,
              "an unknown method dies at B12 with 501");
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
}  // namespace proof

}  // namespace webmachine::flow

#endif
