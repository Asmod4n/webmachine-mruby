// THE internal API: one header, because there is one machine. What the
// components must say to each other lives here - the reactor, the two
// framers, the flow, resources, assets, the websocket half, config.
// src/ carries exactly this one .hpp; whatever a single .cpp needs
// alone belongs in that .cpp.
#ifndef WEBMACHINE_HPP
#define WEBMACHINE_HPP

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/presym.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <liburing.h>
#include <linux/sock_diag.h>  // SK_MEMINFO_*: the kernel's own sndbuf accounting
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>  // struct iovec: a source hands out pointers, not bytes
#include <sys/un.h>
#include <unistd.h>
#include <zlib.h>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// ------------------------------------------------------------------
// The webmachine decision graph, v3, AS DATA. The specification is
// webmachine-ruby's lib/webmachine/decision/flow.rb: every node keeps
// that file's name, callback and both edges; every decision names the
// RFC clause it executes. No interpreter lives here - the table is the
// state model, and the compile-time walk below proves it terminates.
//
// Each node declares WHERE its decision comes from, because that is
// what the tiers are built from:
//   kRequest  - the parsed request (method, header presence, machine
//               state already at hand). NEVER enters the VM.
//   kResource - a resource callback answers. Konst per resource class
//               collapses the node into the graph; otherwise it is one
//               budgeted VM entry (measured: 95-191ns cached-sym).
//   kConneg   - a resource-provided list negotiated against a request
//               header; konst when the list is constant.
//   kAction   - performs the request's work (delete, create, body).


namespace webmachine::flow {

enum class Node : uint8_t {
  kB13, kB12, kB11, kB10, kB9, kB9a, kB9b, kB8, kB7, kB6, kB5, kB4, kB3,
  kC3, kC4, kD4, kD5, kE5, kE6, kF6, kF7,
  kG7, kG8, kG9, kG11, kH7, kH10, kH11, kH12,
  kI4, kI7, kI12, kI13, kJ18,
  kK5, kK7, kK13, kL5, kL7, kL13, kL14, kL15, kL17,
  kM5, kM7, kM16, kM20, kM20b,
  kN5, kN11, kN16,
  kO14, kO16, kO18, kO18b, kO20,
  kP3, kP11,
  kCount
};

enum class Kind : uint8_t { kRequest, kResource, kConneg, kAction };

// An edge either continues to a node or halts with a status.
struct Target {
  Node node;
  uint16_t status;  // != 0: the flow halts here
};
constexpr Target to(Node n) { return {n, 0}; }
constexpr Target halt(uint16_t s) { return {Node::kCount, s}; }

struct FlowNode {
  Node id;
  Kind kind;
  const char* callback;  // webmachine-ruby's name - THE spec; nullptr = none
  const char* clause;    // what the decision executes / notes on hidden work
  Target on_true;
  Target on_false;
};

// The v3 graph, verbatim from flow.rb. "true" is each method's first
// outcome as written there.
inline constexpr FlowNode kFlow[] = {
    // --- B column: request validity, top to bottom -------------------
    {Node::kB13, Kind::kResource, "service_available?", "RFC 9110 15.6.4 (503)",
     to(Node::kB12), halt(503)},
    {Node::kB12, Kind::kResource, "known_methods", "RFC 9110 15.6.2 (501); list x method",
     to(Node::kB11), halt(501)},
    {Node::kB11, Kind::kResource, "uri_too_long?", "RFC 9110 15.5.15 (414)",
     halt(414), to(Node::kB10)},
    {Node::kB10, Kind::kResource, "allowed_methods", "RFC 9110 15.5.6 (405) + 10.2.1 Allow",
     to(Node::kB9), halt(405)},
    {Node::kB9, Kind::kRequest, nullptr, "RFC 1864 (historic): Content-MD5 present?",
     to(Node::kB9a), to(Node::kB9b)},
    {Node::kB9a, Kind::kResource, "validate_content_checksum", "RFC 1864: checksum match or 400",
     to(Node::kB9b), halt(400)},
    {Node::kB9b, Kind::kResource, "malformed_request?", "RFC 9110 15.5.1 (400)",
     halt(400), to(Node::kB8)},
    {Node::kB8, Kind::kResource, "is_authorized?", "RFC 9110 15.5.2 (401) + 11.6.1 WWW-Authenticate",
     to(Node::kB7), halt(401)},
    {Node::kB7, Kind::kResource, "forbidden?", "RFC 9110 15.5.4 (403)",
     halt(403), to(Node::kB6)},
    {Node::kB6, Kind::kResource, "valid_content_headers?", "RFC 9110 15.6.2 (501); Content-* set",
     to(Node::kB5), halt(501)},
    {Node::kB5, Kind::kResource, "known_content_type?", "RFC 9110 15.5.16 (415)",
     to(Node::kB4), halt(415)},
    {Node::kB4, Kind::kResource, "valid_entity_length?", "RFC 9110 15.5.14 (413)",
     to(Node::kB3), halt(413)},
    {Node::kB3, Kind::kRequest, "options", "RFC 9110 9.3.7: OPTIONS answers 200 from options()",
     halt(200), to(Node::kC3)},

    // --- C..F: content negotiation -----------------------------------
    // C3/D4/E5/F6 DECIDE on header presence (request); the resource
    // list only feeds the default negotiation noted in the clause.
    {Node::kC3, Kind::kRequest, "content_types_provided",
     "RFC 9110 12.5.1: Accept absent takes the first provided type",
     to(Node::kC4), to(Node::kD4)},
    {Node::kC4, Kind::kConneg, "content_types_provided", "RFC 9110 12.5.1 / 15.5.7 (406)",
     to(Node::kD4), halt(406)},
    {Node::kD4, Kind::kRequest, "languages_provided",
     "RFC 9110 12.5.4: absent negotiates '*' and may still 406",
     to(Node::kD5), to(Node::kE5)},
    {Node::kD5, Kind::kConneg, "languages_provided", "RFC 9110 12.5.4 / 15.5.7 (406)",
     to(Node::kE5), halt(406)},
    {Node::kE5, Kind::kRequest, "charsets_provided",
     "RFC 9110 12.5.2: absent negotiates '*' and may still 406",
     to(Node::kE6), to(Node::kF6)},
    {Node::kE6, Kind::kConneg, "charsets_provided", "RFC 9110 12.5.2 / 15.5.7 (406)",
     to(Node::kF6), halt(406)},
    {Node::kF6, Kind::kRequest, "encodings_provided",
     "RFC 9110 12.5.3: absent negotiates identity;q=1,*;q=0.5; Content-Type header lands here",
     to(Node::kF7), to(Node::kG7)},
    {Node::kF7, Kind::kConneg, "encodings_provided", "RFC 9110 12.5.3 / 15.5.7 (406)",
     to(Node::kG7), halt(406)},

    // --- G..L: existence and preconditions ---------------------------
    {Node::kG7, Kind::kResource, "resource_exists?", "RFC 9110 12.5.5: Vary lands here",
     to(Node::kG8), to(Node::kH7)},
    {Node::kG8, Kind::kRequest, nullptr, "RFC 9110 13.1.1: If-Match present?",
     to(Node::kG9), to(Node::kH10)},
    {Node::kG9, Kind::kRequest, nullptr, "RFC 9110 13.1.1: If-Match is '*'?",
     to(Node::kH10), to(Node::kG11)},
    {Node::kG11, Kind::kResource, "generate_etag", "RFC 9110 13.1.1 / 15.5.13 (412)",
     to(Node::kH10), halt(412)},
    {Node::kH7, Kind::kRequest, nullptr,
     "RFC 9110 13.1.1: If-Match '*' against a missing resource is 412",
     halt(412), to(Node::kI7)},
    {Node::kH10, Kind::kRequest, nullptr, "RFC 9110 13.1.4: If-Unmodified-Since present?",
     to(Node::kH11), to(Node::kI12)},
    {Node::kH11, Kind::kRequest, nullptr, "RFC 9110 5.6.7: IUS parses as HTTP-date?",
     to(Node::kH12), to(Node::kI12)},
    {Node::kH12, Kind::kResource, "last_modified", "RFC 9110 13.1.4 / 15.5.13 (412)",
     halt(412), to(Node::kI12)},
    {Node::kI4, Kind::kResource, "moved_permanently?", "RFC 9110 15.4.2 (301) + Location",
     halt(301), to(Node::kP3)},
    {Node::kI7, Kind::kRequest, nullptr, "RFC 9110 9.3.4: PUT?",
     to(Node::kI4), to(Node::kK7)},
    {Node::kI12, Kind::kRequest, nullptr, "RFC 9110 13.1.2: If-None-Match present?",
     to(Node::kI13), to(Node::kL13)},
    {Node::kI13, Kind::kRequest, nullptr, "RFC 9110 13.1.2: If-None-Match is '*'?",
     to(Node::kJ18), to(Node::kK13)},
    {Node::kJ18, Kind::kRequest, nullptr,
     "RFC 9110 13.1.2: GET/HEAD gets 304 (15.4.5), others 412 (15.5.13)",
     halt(304), halt(412)},
    {Node::kK5, Kind::kResource, "moved_permanently?", "RFC 9110 15.4.2 (301) + Location",
     halt(301), to(Node::kL5)},
    {Node::kK7, Kind::kResource, "previously_existed?", "RFC 9110 15.4/15.5: gone vs never",
     to(Node::kK5), to(Node::kL7)},
    {Node::kK13, Kind::kResource, "generate_etag", "RFC 9110 13.1.2: ETag in If-None-Match?",
     to(Node::kJ18), to(Node::kL13)},
    {Node::kL5, Kind::kResource, "moved_temporarily?", "RFC 9110 15.4.8 (307) + Location",
     halt(307), to(Node::kM5)},
    {Node::kL7, Kind::kRequest, nullptr, "RFC 9110 15.5.5 (404): only POST may proceed",
     to(Node::kM7), halt(404)},
    {Node::kL13, Kind::kRequest, nullptr, "RFC 9110 13.1.3: If-Modified-Since present?",
     to(Node::kL14), to(Node::kM16)},
    {Node::kL14, Kind::kRequest, nullptr, "RFC 9110 5.6.7: IMS parses as HTTP-date?",
     to(Node::kL15), to(Node::kM16)},
    {Node::kL15, Kind::kRequest, nullptr, "RFC 9110 13.1.3: IMS in the future is ignored",
     to(Node::kM16), to(Node::kL17)},
    {Node::kL17, Kind::kResource, "last_modified", "RFC 9110 13.1.3 / 15.4.5 (304)",
     to(Node::kM16), halt(304)},

    // --- M..P: methods act -------------------------------------------
    {Node::kM5, Kind::kRequest, nullptr, "RFC 9110 15.5.11 (410): only POST may revive",
     to(Node::kN5), halt(410)},
    {Node::kM7, Kind::kResource, "allow_missing_post?", "RFC 9110 9.3.3 / 15.5.5 (404)",
     to(Node::kN11), halt(404)},
    {Node::kM16, Kind::kRequest, nullptr, "RFC 9110 9.3.5: DELETE?",
     to(Node::kM20), to(Node::kN16)},
    {Node::kM20, Kind::kAction, "delete_resource", "RFC 9110 9.3.5; false is 500 (15.6.1)",
     to(Node::kM20b), halt(500)},
    {Node::kM20b, Kind::kResource, "delete_completed?", "RFC 9110 15.3.3 (202) when async",
     to(Node::kO20), halt(202)},
    {Node::kN5, Kind::kResource, "allow_missing_post?", "RFC 9110 9.3.3 / 15.5.11 (410)",
     to(Node::kN11), halt(410)},
    {Node::kN11, Kind::kAction, "post_is_create?",
     "RFC 9110 9.3.3: create_path/base_uri or process_post; redirect is 303 (15.4.4)",
     halt(303), to(Node::kP11)},
    {Node::kN16, Kind::kRequest, nullptr, "RFC 9110 9.3.3: POST?",
     to(Node::kN11), to(Node::kO16)},
    {Node::kO14, Kind::kAction, "is_conflict?",
     "RFC 9110 15.5.10 (409); false runs content_types_accepted (accept_helper)",
     halt(409), to(Node::kP11)},
    {Node::kO16, Kind::kRequest, nullptr, "RFC 9110 9.3.4: PUT?",
     to(Node::kO14), to(Node::kO18)},
    {Node::kO18, Kind::kAction, "content_types_provided",
     "GET/HEAD render the body through the negotiated handler; caching headers land here",
     to(Node::kO18b), to(Node::kO18b)},
    {Node::kO18b, Kind::kResource, "multiple_choices?", "RFC 9110 15.4.1 (300) / 15.3.1 (200)",
     halt(300), halt(200)},
    {Node::kO20, Kind::kRequest, nullptr, "RFC 9110 15.3.5 (204): response carries no entity",
     to(Node::kO18), halt(204)},
    {Node::kP3, Kind::kAction, "is_conflict?",
     "RFC 9110 15.5.10 (409); false runs content_types_accepted (accept_helper)",
     halt(409), to(Node::kP11)},
    {Node::kP11, Kind::kRequest, nullptr, "RFC 9110 15.3.2 (201): Location was set",
     halt(201), to(Node::kO20)},
};

inline constexpr size_t kNodeCount = sizeof(kFlow) / sizeof(kFlow[0]);
static_assert(kNodeCount == static_cast<size_t>(Node::kCount), "one entry per node");

// The table is indexed by its own ids - position and id must agree.
constexpr bool ids_in_order() {
  for (size_t i = 0; i < kNodeCount; i++) {
    if (kFlow[i].id != static_cast<Node>(i)) return false;
  }
  return true;
}
static_assert(ids_in_order(), "kFlow order must match Node order");

// Every edge points at a real node or halts with a real status.
constexpr bool edge_valid(const Target& t) {
  if (t.status == 0) return t.node < Node::kCount;
  return t.status >= 100 && t.status <= 599;
}
constexpr bool edges_valid() {
  for (size_t i = 0; i < kNodeCount; i++) {
    if (!edge_valid(kFlow[i].on_true) || !edge_valid(kFlow[i].on_false)) return false;
  }
  return true;
}
static_assert(edges_valid(), "every edge continues or halts");

// The graph must terminate: from the start, every path reaches a halt
// within the node count - a cycle would overrun the depth bound.
constexpr bool terminates(Node n, size_t depth) {
  if (depth > kNodeCount) return false;
  const FlowNode& f = kFlow[static_cast<size_t>(n)];
  const bool t = f.on_true.status != 0 || terminates(f.on_true.node, depth + 1);
  const bool fl = f.on_false.status != 0 || terminates(f.on_false.node, depth + 1);
  return t && fl;
}
static_assert(terminates(Node::kB13, 0), "the flow is acyclic from B13");

// Every node is reachable from B13 - dead entries would be untested lies.
constexpr void mark(Node n, bool (&seen)[kNodeCount]) {
  const size_t i = static_cast<size_t>(n);
  if (seen[i]) return;
  seen[i] = true;
  const FlowNode& f = kFlow[i];
  if (f.on_true.status == 0) mark(f.on_true.node, seen);
  if (f.on_false.status == 0) mark(f.on_false.node, seen);
}
constexpr bool all_reachable() {
  bool seen[kNodeCount] = {};
  mark(Node::kB13, seen);
  for (bool s : seen) {
    if (!s) return false;
  }
  return true;
}
static_assert(all_reachable(), "every node is reachable from B13");

}  // namespace webmachine::flow

// ------------------------------------------------------------------
// The tier-0 walker: the graph, run with the request's facts and a
// resource's konst answers - ZERO VM entries. A konst vector is
// compiled per resource class AND per method (B12/B10 fold the method
// into the answer at compile time, so the request never re-compares
// method strings at decision points). A node whose answer is not konst
// cannot be walked here; that caller pays tier 1 - one budgeted VM
// entry (95/191ns cached-sym, measured) - when the mruby integration
// lands.



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

// ------------------------------------------------------------------
// The router (#116): ONE constant table per application, marshalled at
// setup out of the token arrays route.add was handed, walked once per
// request. No Ruby object is touched again after add_route returns -
// the tokens live here as bytes and offsets, and matching is memcmp
// over a flat table.
//
// The table is protocol-free on purpose: h1 (Http1::feed, the phr
// request-target) and h2 (Http1::h2_dispatch, the :path pseudo-header)
// walk the SAME table in the SAME registration order, so a route
// cannot mean two things depending on which wire carried it.


namespace webmachine {

// How many bindings one route may carry. A route past this refuses at
// add_route BY NAME, so the match loop below never has to test.
inline constexpr size_t kMaxRouteBindings = 16;

// What a match CAPTURED: the request bytes a Symbol token bound, and
// the splat's tail. Nothing reads them yet.
//
// They exist already because the capture is where the cost would be:
// the match loop has the segment boundaries in registers exactly once,
// while it is walking. Slice 4 (the lazy Request object) turns these
// spans into Ruby values ON DEMAND, inside the run frame, for the
// resources that ask - and a resource that never asks pays for two
// pointer stores that the loop was going to compute anyway. Adding the
// capture later would mean walking the path a second time, which is
// the one shape this router exists to avoid.
//
// NO member initializers, deliberately: this is scratch the match loop
// fills in, and a declaration at the top of a request path would
// otherwise zero 16 spans - 256 bytes of stores per request that
// nothing reads. A successful match sets nbind, has_splat and whatever
// it captured; a miss (-1) leaves all of it indeterminate, and the
// caller has nothing to read on a miss anyway.
struct RouteSpans {
  struct Span {
    const char* p;
    size_t n;
  };
  Span bind[kMaxRouteBindings];
  Span splat;
  uint8_t nbind;
  bool has_splat;
};

class RouteTable {
 public:
  enum Kind : uint8_t { kLiteral, kBinding, kSplat };

  // --- building (add_route only) ------------------------------------
  // A route under construction. abandon() rolls it back whole, so a
  // route that fails validation leaves NOTHING half-registered.
  void open() {
    pending_first_ = toks_.size();
    pending_blob_ = blob_.size();
    pending_binds_ = 0;
    pending_splat_ = false;
  }
  // False: the literal is longer than a token can address.
  bool literal(const char* p, size_t n) {
    if (n > 0xffffu) return false;
    RouteToken t;
    t.kind = kLiteral;
    t.off = static_cast<uint32_t>(blob_.size());
    t.len = static_cast<uint32_t>(n);
    blob_.append(p, n);
    toks_.push_back(t);
    return true;
  }
  // False: past kMaxRouteBindings - refused by name at add_route.
  // `sym` is the Symbol token's own id, kept so the request object
  // (#116 slice 4) can NAME what a span captured. It is an mrb_sym
  // stored as a plain number: this header stays mruby-free, and a
  // symbol id is one anyway.
  bool binding(uint32_t sym) {
    if (pending_binds_ >= kMaxRouteBindings) return false;
    pending_binds_++;
    toks_.push_back(RouteToken{kBinding, sym, 0});
    return true;
  }

  // The name of a route's i-th binding, in the order match() captured
  // them. 0 = no such binding (a caller past nbind).
  uint32_t binding_sym(int route, uint8_t i) const {
    const Route& rt = routes_[static_cast<size_t>(route)];
    uint8_t seen = 0;
    for (uint32_t t = 0; t < rt.count; t++) {
      const RouteToken& tk = toks_[rt.first + t];
      if (tk.kind != kBinding) continue;
      if (seen == i) return tk.off;
      seen++;
    }
    return 0;
  }
  void splat() {
    pending_splat_ = true;
    toks_.push_back(RouteToken{kSplat, 0, 0});
  }
  bool pending_splat() const { return pending_splat_; }
  void commit() {
    Route r;
    r.first = static_cast<uint32_t>(pending_first_);
    r.count = static_cast<uint32_t>(toks_.size() - pending_first_);
    routes_.push_back(r);
  }
  void abandon() {
    toks_.resize(pending_first_);
    blob_.resize(pending_blob_);
  }

  size_t size() const { return routes_.size(); }
  bool empty() const { return routes_.empty(); }

  // --- matching (per request) ---------------------------------------
  // The FIRST route that matches wins (registration order, exactly
  // what route.add promised). -1 = miss; the caller answers 404 from
  // its prebuilt store, before B13 and before any method test.
  int match(const char* path, size_t len, RouteSpans& out) const {
    // RFC 9110 4.2.1: the query is NOT part of the path. It comes off
    // here, once, before any route is compared - the asset tier reads
    // the target the same way (assets.cpp).
    size_t plen = len;
    for (size_t i = 0; i < len; i++) {
      if (path[i] == '?') {
        plen = i;
        break;
      }
    }
    size_t start = 0;
    if (start < plen && path[start] == '/') start++;
    const char* blob = blob_.data();
    const size_t n = routes_.size();
    for (size_t r = 0; r < n; r++) {
      const Route& rt = routes_[r];
      size_t p = start;
      uint8_t nb = 0;
      bool ok = true;
      bool splat = false;
      for (uint32_t t = 0; t < rt.count; t++) {
        const RouteToken& tk = toks_[rt.first + t];
        if (tk.kind == kSplat) {
          // :* is the last token by construction (add_route refuses
          // anything else), so the rest of the path IS the tail -
          // including the empty tail, which is why /fizz matches
          // ['fizz', :*] as well as /fizz/a/b does.
          out.splat.p = path + p;
          out.splat.n = plen - p;
          p = plen;
          splat = true;
          break;
        }
        if (p >= plen) {
          ok = false;
          break;
        }
        const size_t seg = p;
        while (p < plen && path[p] != '/') p++;
        const size_t seglen = p - seg;
        if (tk.kind == kLiteral) {
          if (seglen != tk.len || std::memcmp(path + seg, blob + tk.off, seglen) != 0) {
            ok = false;
            break;
          }
        } else {
          out.bind[nb].p = path + seg;
          out.bind[nb].n = seglen;
          nb++;
        }
        if (p < plen) p++;  // step over the '/'
      }
      if (!ok) continue;
      // Without a splat every segment must have been spoken for -
      // /fizz/buzz is not ['fizz'].
      if (!splat && p < plen) continue;
      out.nbind = nb;
      out.has_splat = splat;
      return static_cast<int>(r);
    }
    return -1;
  }

 private:
  struct RouteToken {
    Kind kind;
    uint32_t off;  // into blob_ (literals only)
    uint32_t len;
  };
  struct Route {
    uint32_t first;
    uint32_t count;
  };
  std::string blob_;  // every literal's bytes, once
  std::vector<RouteToken> toks_;
  std::vector<Route> routes_;
  size_t pending_first_ = 0;
  size_t pending_blob_ = 0;
  size_t pending_binds_ = 0;
  bool pending_splat_ = false;
};

}  // namespace webmachine

// ------------------------------------------------------------------
// The access log (opt-in): the HOT CORE writes RECORDS, a sibling
// process writes PROSE. Formatting a combined-log line in-process
// measured 71.5ns each - date and number spelling plus an escape scan
// over every request byte; filling a fixed header and memcpying the
// raw strings measures 17ns. So the server ships records over a unix
// socketpair to webmachine-logd (forked by --log, dies with the
// socket), which formats Combined Log Format - the dialect every
// existing reader parses - escapes, and batches to disk on its own
// core, where its 70ns cost nobody.
//
// THE ONE RULE, from the user, verbatim: every line we decide to
// write MUST land on disk. No drop path exists on either side: the
// server's buffer grows until the kernel took the records (the Ring's
// write SQE rides the submit that was happening anyway; a short write
// resumes, a dead daemon is a named refusal), and the daemon's only
// job is to drain, format and write.
//
// This file owns the WIRE CONTRACT between the two: same machine,
// same build, so the struct is the format - no endianness ceremony,
// one version byte so a mismatch refuses instead of misparsing.


namespace webmachine {

// One response. Followed on the wire by tlen+rlen+ulen raw bytes
// (target, referer, user-agent) and plen peer bytes.
struct LogRec {
  uint8_t version;   // kLogRecVersion, checked by the daemon
  uint8_t flags;     // kLogH2 | kLogNoTrack
  uint16_t status;
  uint32_t bytes;    // %b; 0 spells "-"
  int64_t sec;       // unix time of the answer; the daemon spells it
  uint8_t mlen;      // method bytes follow the header first
  uint8_t plen;      // then the peer's RAW sockaddr (0 = none/unix)
  uint16_t tlen;
  uint16_t rlen;
  uint16_t ulen;
};
inline constexpr uint8_t kLogRecVersion = 3;
inline constexpr uint8_t kLogH2 = 1;  // spell "HTTP/2", not "HTTP/1.1"
// The peer sent DNT: 1 or Sec-GPC: 1 - "do not track me". Respected:
// the daemon caps this record's %h at anon even when the operator
// chose privacy `none`. (A future debug build with tracing active
// will log everything by design - the user's stated exception.)
inline constexpr uint8_t kLogNoTrack = 2;

struct AccessLog {
  bool enabled = false;
  std::string buf;
  std::string flight;
  bool in_flight = false;
  int64_t sec = 0;  // refreshed once per second by on_tick

  void line(const void* peer, size_t plen, const char* method, size_t mlen, const char* target,
            size_t tlen, uint8_t flags, uint16_t status, size_t body_bytes, const char* ref,
            size_t rlen, const char* ua, size_t ulen) {
    // Truncation caps are the wire fields' widths; a 64K header is
    // kMaxHead-bounded before it ever gets here.
    if (mlen > 255) mlen = 255;
    if (plen > 255) plen = 255;
    if (tlen > 65535) tlen = 65535;
    if (rlen > 65535) rlen = 65535;
    if (ulen > 65535) ulen = 65535;
    LogRec r;
    r.version = kLogRecVersion;
    r.flags = flags;
    r.status = status;
    r.bytes = body_bytes > 0xffffffffull ? 0xffffffffu : static_cast<uint32_t>(body_bytes);
    r.sec = sec;
    r.mlen = static_cast<uint8_t>(mlen);
    r.plen = static_cast<uint8_t>(plen);
    r.tlen = static_cast<uint16_t>(tlen);
    r.rlen = static_cast<uint16_t>(rlen);
    r.ulen = static_cast<uint16_t>(ulen);
    buf.append(reinterpret_cast<const char*>(&r), sizeof r);
    if (mlen != 0) buf.append(method, mlen);
    if (plen != 0) buf.append(static_cast<const char*>(peer), plen);
    if (tlen != 0) buf.append(target, tlen);
    if (rlen != 0) buf.append(ref, rlen);
    if (ulen != 0) buf.append(ua, ulen);
  }
};

}  // namespace webmachine

// ------------------------------------------------------------------
// The version-free HTTP layer: RFC 9110 semantics as pure inline
// functions and data. No state, no wire syntax - status lines,
// Connection handling, chunked framing and phr are 9112 property and
// stay in http1 (9113's frames will stay in http2). Sharing happens
// at zero cost: everything here inlines into its caller, so the
// machine code is identical to the copy it replaced.



namespace webmachine::http {

// Case-insensitive equality against a lowercase literal (header names
// are case-insensitive, RFC 9110 §5.1).
constexpr bool tok_eq(const char* s, size_t n, const char* lit, size_t litn) {
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// If-Match / If-None-Match spell "any" as * (RFC 9110 §13.1.1/13.1.2);
// a quoted "*" arrives from some clients and means the same.
constexpr bool star_value(const char* v, size_t n) {
  if (n == 1 && v[0] == '*') return true;
  return n == 3 && v[0] == '"' && v[1] == '*' && v[2] == '"';
}

// Methods are case-sensitive tokens (RFC 9110 §9.1).
// RFC 9110 4.2.1: the query is not part of the path. How long the
// path half of a request-target is - the router splits the same way,
// and the request object (#116 slice 4) reads the same boundary.
inline size_t path_only(const char* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (p[i] == '?') return i;
  }
  return n;
}

inline flow::Method parse_method(const char* m, size_t n) {
  switch (n) {
    case 3:
      if (std::memcmp(m, "GET", 3) == 0) return flow::Method::kGet;
      if (std::memcmp(m, "PUT", 3) == 0) return flow::Method::kPut;
      break;
    case 4:
      if (std::memcmp(m, "HEAD", 4) == 0) return flow::Method::kHead;
      if (std::memcmp(m, "POST", 4) == 0) return flow::Method::kPost;
      break;
    case 6:
      if (std::memcmp(m, "DELETE", 6) == 0) return flow::Method::kDelete;
      break;
    case 7:
      if (std::memcmp(m, "OPTIONS", 7) == 0) return flow::Method::kOptions;
      break;
    default:
      break;
  }
  return flow::Method::kOther;
}

// text/* with no parameters gets "; charset=utf-8" appended - a
// statement of fact, not a guess: mruby produces UTF-8 or bytes,
// nothing else exists in this VM, and a text/plain response without a
// charset decodes by the BROWSER'S locale default (windows-1252 in
// Western locales). text/* only: application/json's registration has
// no charset parameter (RFC 8259, JSON is UTF-8), adding one is noise.
// A type already carrying parameters is left alone - a resource that
// spelled its own charset wins. Setup-only; never runs per request.
// EVERY writer goes through here (#146: this tree once shipped two
// serializers that drifted): Http1's konst head + h2 blocks, and the
// asset tier's extension table.
inline std::string with_charset(const std::string& type) {
  if (type.size() < 5 || !tok_eq(type.data(), 5, "text/", 5)) return type;
  if (type.find(';') != std::string::npos) return type;
  return type + "; charset=utf-8";
}

// #147's media-type table: worth compressing a dynamic body of this
// Content-Type? Decided ONCE per resource at Http1's setup (the "8%
// rule" - a media type this narrow gate lets through is the minority,
// so a resource outside it costs no branch at answer time, only this
// one bool). Structural, not a guess: text/* always compresses;
// anything ending +json or +xml is a registered structured-syntax
// suffix (RFC 6839) and inherits its base type's compressibility; a
// short named list covers the common textual types that are neither -
// application/json, application/javascript, application/xml,
// application/wasm (a binary format, but one deflate reliably shrinks:
// it is mostly small integer opcodes and LEB128, not entropy), and
// image/svg+xml (XML, mislabeled as an image/ type by history).
// EVERYTHING ELSE, including anything this table has never heard of,
// answers false - conservative downward, because a wrong "yes" spends
// CPU compressing bytes that gain nothing (already-compressed media:
// image/png, video/*, application/zip, ...) while a wrong "no" only
// ever costs bytes on the wire, never correctness. Any parameters
// (";...", most commonly a charset) are ignored - the media type
// itself answers the question, not what follows the semicolon.
constexpr size_t clen(const char* s) {
  size_t n = 0;
  while (s[n] != '\0') n++;
  return n;
}
constexpr bool compressible_media_type(const char* v, size_t n) {
  size_t tn = 0;
  while (tn < n && v[tn] != ';') tn++;
  if (tn >= 5 && tok_eq(v, 5, "text/", 5)) return true;
  if (tn >= 5 && tok_eq(v + tn - 5, 5, "+json", 5)) return true;  // RFC 6839
  if (tn >= 4 && tok_eq(v + tn - 4, 4, "+xml", 4)) return true;   // RFC 6839
  constexpr const char* kExact[] = {
      "application/json", "application/javascript", "application/xml",
      "application/wasm", "image/svg+xml",
  };
  for (const char* lit : kExact) {
    if (tok_eq(v, tn, lit, clen(lit))) return true;
  }
  return false;
}
inline bool compressible_media_type(const std::string& v) {
  return compressible_media_type(v.data(), v.size());
}
namespace proof {
constexpr bool ct(const char* s) { return compressible_media_type(s, clen(s)); }
static_assert(ct("text/html"), "text/* compresses");
static_assert(ct("text/html; charset=utf-8"), "a parameter does not hide the media type");
static_assert(ct("application/json"));
static_assert(ct("application/javascript"));
static_assert(ct("application/xml"));
static_assert(ct("application/wasm"));
static_assert(ct("image/svg+xml"));
static_assert(ct("application/vnd.api+json"), "RFC 6839 +json suffix");
static_assert(ct("application/rss+xml"), "RFC 6839 +xml suffix");
static_assert(!ct("image/png"), "already-compressed media stays no");
static_assert(!ct("application/octet-stream"), "unknown is conservative no");
static_assert(!ct(""), "empty is no, not a crash");
}  // namespace proof

// The status names of RFC 9110 §15.
constexpr const char* reason(uint16_t status) {
  switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 300: return "Multiple Choices";
    case 301: return "Moved Permanently";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 416: return "Range Not Satisfiable";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
  }
  return "Response";
}

// The Date field value's fixed shape (RFC 9110 §5.6.7 IMF-fixdate);
// writers may prebuild with the placeholder and patch exactly these
// 29 bytes per second.
inline constexpr char kDatePlaceholder[] = "Sun, 00 Jan 1970 00:00:00 GMT";
inline constexpr size_t kDateLen = sizeof(kDatePlaceholder) - 1;

// IMF-fixdate by hand: strftime's %a/%b obey the process locale and
// would emit German day names under LC_TIME=de_DE.
inline void date_core(char out[kDateLen], const struct tm& tm) {
  static const char kDay[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  const auto two = [&](size_t at, int v) {
    out[at] = static_cast<char>('0' + v / 10);
    out[at + 1] = static_cast<char>('0' + v % 10);
  };
  std::memcpy(out, kDay[tm.tm_wday], 3);
  out[3] = ',';
  out[4] = ' ';
  two(5, tm.tm_mday);
  out[7] = ' ';
  std::memcpy(out + 8, kMon[tm.tm_mon], 3);
  out[11] = ' ';
  const int year = tm.tm_year + 1900;
  two(12, year / 100);
  two(14, year % 100);
  out[16] = ' ';
  two(17, tm.tm_hour);
  out[19] = ':';
  two(20, tm.tm_min);
  out[22] = ':';
  two(23, tm.tm_sec);
  out[25] = ' ';
  std::memcpy(out + 26, "GMT", 3);
}

// "Content-Length: N\r\n\r\n" spelled by hand (RFC 9110 §8.6): printf
// machinery has no business on the request path. Returns the length.
inline size_t spell_content_length(char (&buf)[40], size_t len) {
  std::memcpy(buf, "Content-Length: ", 16);
  size_t at = 16;
  char digits[20];
  size_t d = 0;
  size_t v = len;
  do {
    digits[d++] = static_cast<char>('0' + v % 10);
    v /= 10;
  } while (v != 0);
  while (d != 0) buf[at++] = digits[--d];
  buf[at++] = '\r';
  buf[at++] = '\n';
  buf[at++] = '\r';
  buf[at++] = '\n';
  return at;
}

// Content-Length is 1*DIGIT (RFC 9110 §8.6). kOk fills *out; kBad is
// a syntax violation (the caller's 400), kOverflow exceeds size_t
// (the caller's refusal bound, 413).
enum class ClStatus : uint8_t { kOk, kBad, kOverflow };
inline ClStatus parse_content_length(const char* s, size_t n, size_t* out) {
  if (n == 0) return ClStatus::kBad;
  size_t v = 0;
  for (size_t j = 0; j < n; j++) {
    const char ch = s[j];
    if (ch < '0' || ch > '9') return ClStatus::kBad;
    size_t t = 0;
    if (__builtin_mul_overflow(v, static_cast<size_t>(10), &t) ||
        __builtin_add_overflow(t, static_cast<size_t>(ch - '0'), &v)) {
      return ClStatus::kOverflow;
    }
  }
  *out = v;
  return ClStatus::kOk;
}

// The value tier's first residents (#165, first customer #170): the
// header VALUES negotiation reads. The pointers BORROW the receive
// buffer (h1) or the decode buffer (h2) and die with the dispatch that
// filled them - presence lives in ReqFacts' has_* flags, these only
// say where the bytes are while the answer is being made.
struct ReqValues {
  // For the access log alone (opt-in): the two combined-format fields
  // that are neither facts nor wire framing. Captured in the same one
  // header switch every request already pays; borrows die with the
  // request's answer like every other value here.
  const char* log_ref = nullptr;
  size_t log_ref_len = 0;
  const char* log_ua = nullptr;
  size_t log_ua_len = 0;

  const char* accept_encoding = nullptr;
  size_t accept_encoding_len = 0;
  const char* if_match = nullptr;
  size_t if_match_len = 0;
  const char* if_none_match = nullptr;
  size_t if_none_match_len = 0;
  // Range/If-Range never touch the graph (webmachine has no range
  // node - a representation concern, not a decision one), so they set
  // no fact and leave `plain` alone; only the asset tier reads them.
  const char* range = nullptr;
  size_t range_len = 0;
  const char* if_range = nullptr;
  size_t if_range_len = 0;
};

// Range: bytes=first-last | first- | -suffix, ONE range only (RFC 9110
// §14.1.2). kNone = act as if the field were absent - a server MAY
// ignore Range entirely (§14.2), so a multi-range request, a foreign
// unit or a malformed value degrades to the full 200, stated here
// rather than discovered. kUnsat = 416 (§15.5.17). `complete` counts
// the SELECTED representation's octets - for a Content-Encoding: gzip
// response that is the compressed stream (§14.1.2; ranging the
// uncompressed bytes under a gzip coding would be silent corruption).
enum class RangeParse : uint8_t { kNone, kOne, kUnsat };
inline RangeParse parse_range(const char* v, size_t n, size_t complete, size_t* first,
                              size_t* last) {
  if (n < 7 || !tok_eq(v, 6, "bytes=", 6)) return RangeParse::kNone;
  size_t i = 6;
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  const auto digits = [&](size_t* out) -> bool {  // 1*DIGIT, overflow-checked
    bool any = false;
    size_t val = 0;
    while (i < n && v[i] >= '0' && v[i] <= '9') {
      size_t t = 0;
      if (__builtin_mul_overflow(val, static_cast<size_t>(10), &t) ||
          __builtin_add_overflow(t, static_cast<size_t>(v[i] - '0'), &val)) {
        return false;
      }
      any = true;
      i++;
    }
    *out = val;
    return any;
  };
  size_t a = 0, b = 0;
  const bool have_a = digits(&a);
  if (i >= n || v[i] != '-') return RangeParse::kNone;
  i++;
  const bool have_b = digits(&b);
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  if (i != n) return RangeParse::kNone;  // a second range or trailing junk: ignore
  if (!have_a && !have_b) return RangeParse::kNone;
  if (complete == 0) return RangeParse::kUnsat;  // no byte satisfies any range
  if (!have_a) {  // -suffix: the final b octets
    if (b == 0) return RangeParse::kUnsat;
    *first = b >= complete ? 0 : complete - b;
    *last = complete - 1;
    return RangeParse::kOne;
  }
  if (have_b && b < a) return RangeParse::kNone;  // malformed: ignore
  if (a >= complete) return RangeParse::kUnsat;
  *first = a;
  *last = have_b ? (b < complete - 1 ? b : complete - 1) : complete - 1;
  return RangeParse::kOne;
}

// If-Range holds ONE validator (RFC 9110 §14.2): an entity-tag,
// compared STRONGLY (a weak tag can never match), or an HTTP-date -
// unparsed here, and an unmatched validator lawfully serves the full
// 200, so a date reads as "no match" and stays correct.
inline bool if_range_matches(const char* v, size_t n, const char* tag, size_t taglen) {
  size_t i = 0;
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  size_t e = n;
  while (e > i && (v[e - 1] == ' ' || v[e - 1] == '\t')) e--;
  return e - i == taglen && std::memcmp(v + i, tag, taglen) == 0;
}

// Accept-Encoding, asked the one question this tree has: may gzip be
// sent? (RFC 9110 §12.5.3.) Most specific wins: an explicit gzip (or
// its x-gzip alias, §12.5.3) decides by its own q; otherwise * decides;
// otherwise - the field is present but names neither - gzip is not
// acceptable. An empty value means "no codings": also not acceptable.
// Callers only ask when the field EXISTS; a missing field means any
// coding is acceptable and never reaches this parse.
inline bool gzip_acceptable(const char* v, size_t n) {
  bool gz_seen = false, gz_ok = false, star_seen = false, star_ok = false;
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
    const size_t ts = i;
    while (i < n && v[i] != ',' && v[i] != ';' && v[i] != ' ' && v[i] != '\t') i++;
    const size_t tl = i - ts;
    // Parameters up to the next element; q's digits decide (weight is
    // 0[.000]..1[.000], so "any nonzero digit" IS "q > 0").
    bool q_nonzero = true;
    while (i < n && v[i] != ',') {
      if (v[i] != ';') {
        i++;
        continue;
      }
      i++;
      while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
      if (i < n && (v[i] == 'q' || v[i] == 'Q')) {
        size_t j = i + 1;
        while (j < n && (v[j] == ' ' || v[j] == '\t')) j++;
        if (j < n && v[j] == '=') {
          j++;
          q_nonzero = false;
          while (j < n && v[j] != ',' && v[j] != ';') {
            if (v[j] >= '1' && v[j] <= '9') q_nonzero = true;
            j++;
          }
          i = j;
        }
      }
    }
    if (tl != 0) {
      if (tok_eq(v + ts, tl, "gzip", 4) || tok_eq(v + ts, tl, "x-gzip", 6)) {
        gz_seen = true;
        gz_ok = q_nonzero;
      } else if (tl == 1 && v[ts] == '*') {
        star_seen = true;
        star_ok = q_nonzero;
      }
    }
  }
  if (gz_seen) return gz_ok;
  if (star_seen) return star_ok;
  return false;
}

// Does an If-Match/If-None-Match list contain `tag` (the full quoted
// form)? If-None-Match compares weakly - a W/ prefix is stripped and
// ignored (RFC 9110 §13.1.2); If-Match compares strongly, so a weak
// member can never match there (§13.1.1). The * form never reaches
// this parse - ReqFacts carries it as a fact.
inline bool etag_list_match(const char* v, size_t n, const char* tag, size_t taglen,
                            bool weak) {
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
    if (i >= n) break;
    bool member_weak = false;
    if (i + 1 < n && v[i] == 'W' && v[i + 1] == '/') {
      member_weak = true;
      i += 2;
    }
    if (i >= n || v[i] != '"') {
      // Not an entity-tag; skip to the next element rather than trust
      // the rest of a malformed list.
      while (i < n && v[i] != ',') i++;
      continue;
    }
    const size_t start = i;
    i++;
    while (i < n && v[i] != '"') i++;
    if (i >= n) break;  // unterminated: nothing more to compare
    i++;
    const size_t mlen = i - start;
    if ((weak || !member_weak) && mlen == taglen &&
        std::memcmp(v + start, tag, taglen) == 0) {
      return true;
    }
  }
  return false;
}

// One length-switch per header - the hot-path shape stays ONE dispatch.
// The 9110 facts (conneg, preconditions, content-md5) are filled here;
// every name this layer does not own falls through to the framer's
// functor (9112 owns host/connection/transfer-encoding/content-length;
// 9113 owns none of them, §8.2.2). The functor inlines at each call
// site, where the case's length is a known constant - the compiler
// folds its checks to exactly the arms the old fused switch had.
template <class OnWire>
inline void header_switch(const char* name, size_t nlen, const char* value, size_t vlen,
                          flow::ReqFacts& facts, ReqValues& vals, OnWire&& wire) {
  switch (nlen) {
    case 3:
      // DNT is formally discontinued but still widely sent; Sec-GPC
      // (below) is its successor. "1" is the only defined opt-out
      // value - "0" is explicit consent and stays false. Neither is
      // a flow fact: `plain` is untouched, the graph decides nothing
      // by it; only the access log reads no_track.
      if (tok_eq(name, nlen, "dnt", 3)) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return;
      }
      break;
    case 5:
      if (tok_eq(name, nlen, "range", 5)) {
        vals.range = value;  // no fact, no plain: the graph has no range node
        vals.range_len = vlen;
        return;
      }
      break;
    case 6:
      if (tok_eq(name, nlen, "accept", 6)) {
        facts.has_accept = true;
        facts.plain = false;
        return;
      }
      break;
    case 7:
      // Sec-GPC: 1 (Global Privacy Control) - same meaning, same
      // single defined value as DNT above. Other 7-byte names
      // (referer, upgrade) fall through to the framer's functor.
      if (tok_eq(name, nlen, "sec-gpc", 7)) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return;
      }
      break;
    case 8:
      if (tok_eq(name, nlen, "if-range", 8)) {
        vals.if_range = value;  // like range: representation-level only
        vals.if_range_len = vlen;
        return;
      }
      if (tok_eq(name, nlen, "if-match", 8)) {
        facts.has_if_match = true;
        facts.plain = false;
        facts.if_match_star = star_value(value, vlen);
        vals.if_match = value;
        vals.if_match_len = vlen;
        return;
      }
      break;
    case 11:
      if (tok_eq(name, nlen, "content-md5", 11)) {
        facts.has_content_md5 = true;
        facts.plain = false;
        return;
      }
      break;
    case 13:
      if (tok_eq(name, nlen, "if-none-match", 13)) {
        facts.has_if_none_match = true;
        facts.plain = false;
        facts.inm_star = star_value(value, vlen);
        vals.if_none_match = value;
        vals.if_none_match_len = vlen;
        return;
      }
      break;
    case 14:
      if (tok_eq(name, nlen, "accept-charset", 14)) {
        facts.has_accept_charset = true;
        facts.plain = false;
        return;
      }
      break;
    case 15:
      if (tok_eq(name, nlen, "accept-language", 15)) {
        facts.has_accept_language = true;
        facts.plain = false;
        return;
      }
      if (tok_eq(name, nlen, "accept-encoding", 15)) {
        facts.has_accept_encoding = true;
        facts.plain = false;
        vals.accept_encoding = value;
        vals.accept_encoding_len = vlen;
        return;
      }
      break;
    case 17:
      if (tok_eq(name, nlen, "if-modified-since", 17)) {
        // Date parsing is a later tier; an unparsed date reads as
        // invalid, which flow.rb's rescue path also ignores (L14).
        facts.has_if_modified_since = true;
        facts.plain = false;
        return;
      }
      break;
    case 19:
      if (tok_eq(name, nlen, "if-unmodified-since", 19)) {
        facts.has_if_unmodified_since = true;  // date tier pending, like IMS
        facts.plain = false;
        return;
      }
      break;
    default:
      break;
  }
  wire(name, nlen, value, vlen);
}

}  // namespace webmachine::http

// ------------------------------------------------------------------
// The request object (#116 slice 4): what a RUNTIME callback sees of
// the request that is being answered.
//
// LAZY, not eager - the whole point. There is ONE request object in the
// process, a hidden Data handle rooted at init; per request the C side
// swaps the VIEW it points at, which is a pointer store. Every accessor
// materialises its Ruby value when it is CALLED and never before, so a
// resource that asks nothing allocates nothing, and a konst resource
// (which never enters the VM at all) does not even pay the pointer
// store.
//
// Nothing here memoises across calls: the callback's own frame roots
// what it received, and a second call materialises again. That is the
// same lifetime rule the rendered body already lives under, and it is
// why the object needs no ivars, no pinning and no reset.




namespace webmachine {

// What one request lends the VM. Pointers into bytes that live at
// least as long as the run frame - the receive buffer for h1, the
// stream's own copy for a parked h2 request (h2.hpp says why: the
// decode buffer is gone by then).
struct ReqView {
  const char* target = nullptr;  // the request-target as it arrived
  size_t target_len = 0;
  size_t path_len = 0;  // target up to '?' - RFC 9110 4.2.1
  flow::Method method = flow::Method::kGet;
  // The method's own bytes, for the one case the enum cannot spell
  // (kOther). Null where they are not lent; the accessor refuses by
  // name rather than inventing a verb.
  const char* method_p = nullptr;
  size_t method_n = 0;
  // Which route answered and what it captured. `table` is the app's,
  // needed for the binding NAMES - the spans hold only the bytes.
  const RouteTable* table = nullptr;
  int route = -1;
  RouteSpans spans {};
  // The head's fields, LENT where they still exist: h1 hands over the
  // phr_header array off its own frame (two stores, and only in the
  // branch that was going to run a resource anyway). Null is the
  // honest state for a parked h2 request, whose decode buffer is gone
  // by the time it answers - request.headers refuses BY NAME there
  // rather than lending a dead pointer. `void*` because this header
  // stays free of picohttpparser; request.cpp is where the shape is
  // known.
  const void* hdrs = nullptr;
  size_t nhdr = 0;
};

// Webmachine::Request, and Webmachine::Resource#request. Defined once
// at gem init.
void request_init(mrb_state* mrb, struct RClass* wm);

// The run frame's in-slot: resource_run points the one object at this
// request before the frame, and at nothing after it.
void request_bind(const ReqView* view);

}  // namespace webmachine

// ------------------------------------------------------------------
// The resource: Webmachine::Resource is the Ruby base class an app
// subclasses. Two kinds of methods, by declaration:
//   class methods  (def self.x) - konst: asked ONCE at setup, folded
//                                 into the compiled vectors
//   instance methods (def x)    - runtime: answered through the VM on
//                                 EVERY request, inside ONE frame
//
// LIFETIME (#181, Nutzer-Entscheid): the instance lives ONE REQUEST.
// HTTP is stateless, so its resource is: the run frame builds the
// object, the request's callbacks share it, and it dies with the
// frame. Ivars are therefore REQUEST scope - what one callback of a
// request leaves, the next callback of that same request finds, and
// no other request ever sees it. (webmachine-ruby instantiates per
// request for the same reason; this tree did not, and cross-request
// state could leak between strangers.) APPLICATION state lives where
// application state belongs: a mutable object a constant names, or a
// global - never a class ivar, because add_route FREEZES the class.
//
// The runtime tier runs the WHOLE flow inside one VM method (a hidden
// class carries it): within that frame mrb->jmp is armed and the arena
// lives until exit, so callbacks are naked yields, values one callback
// returns stay alive for the next one IN THE ARENA (cheaper than any
// ivar), and the rendered body is copied out while the frame roots it.
// This frame IS the memory model - a per-node-entry variant measured
// 26ns faster on one callback (forgecore 230 vs 256ns) and was removed
// anyway: it cannot host cross-callback lifetimes without ivars.




namespace webmachine {

struct Resource {
  flow::KonstSet konst;
  mrb_state* mrb = nullptr;
  // The class, FROZEN at add_route: nobody can redefine a method after
  // routes are added, so everything resolved below stays true forever.
  struct RClass* klass = nullptr;
  uint64_t dynamic = 0;  // nodes answered per request
  mrb_sym node_sym[flow::kNodeCount] = {};  // presym constants, never interned
  // Resolved ONCE at add_route (aliases unwrapped): a Ruby proc enters
  // directly via mrb_yield_with_class, skipping the funcall machinery;
  // a cfunc or undef falls back to funcall (reproducing vm.c's frame
  // setup is not worth owning).
  mrb_method_t node_m[flow::kNodeCount] = {};
  bool node_fast[flow::kNodeCount] = {};
  bool dynamic_body = false;
  mrb_sym body_sym = {};
  mrb_method_t body_m = {};
  bool body_fast = false;
  // #147: does this resource's encodings_provided (class method, read
  // once here like content_type) name "gzip" among its keys? The
  // Hash's VALUES (encoder methods, webmachine-ruby's own dispatch)
  // are not honored by any tier yet and are ignored on purpose - only
  // key presence is read. Http1 combines this with the media-type
  // table (its own setup-time decision) into the one bit a response
  // actually gates on.
  bool gzip_offered = false;
  // The run method's carrier object (hidden class - no constant, Ruby
  // code cannot reach or reopen it). Its cfunc finds this Resource
  // through the proc's env (a cptr), never through mrb->ud.
  mrb_value run_self = {};
  // The run frame's in/out slots, valid for one resource_run call.
  // `live` is THE REQUEST'S resource instance (#181): built at the top
  // of the frame, receiver of every callback in it, dropped when it
  // returns. No mrb_gc_register: the frame's arena roots it, which is
  // the whole reason the flow runs inside one frame.
  mutable mrb_value live = {};
  mutable const flow::ReqFacts* run_facts = nullptr;
  mutable std::string* run_body = nullptr;
  mutable bool run_have_body = false;
  mutable uint16_t run_status = 0;
};

// Folds ONE resource class into `out`: every konst callback asked once,
// every dynamic callback resolved, the class frozen. Called by
// route.add (#116) and nowhere else - the constant scan that used to
// find "the" resource class is gone. False leaves the reason in err;
// what no tier can honor refuses the start by name, never silently.
// NOTE: `out` must live at its final address (the run env borrows it).
bool resource_fold(mrb_state* mrb, mrb_value klass, Resource& out, char* err, size_t errlen);

// THE runtime path: decision + render inside one VM call. The rendered
// body (if any) is copied into *body while the frame still roots it.
// A raising callback leaves its exception pending and returns 500.
// `req` is what the callbacks see of the request (#116 slice 4): bound
// for the frame's duration and unbound after it, so nothing can read a
// view whose bytes are gone. Null is legal and means the same thing.
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, const ReqView* req,
                      std::string* body, bool* have_body);

// The pending exception's message, read straight from RException's
// mesg field and LENT: copy the bytes before the next mruby call - no
// allocation happens in between, so nothing can collect them.
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);

}  // namespace webmachine

// ------------------------------------------------------------------
// Dynamic-body gzip (#147): the SAME wire shape assets.cpp hand-builds
// for a ZIP method-8 entry - RFC 1952 header + trailer around a raw
// DEFLATE stream - built here at REQUEST time instead of read from a
// mapping, because a dynamic body does not exist until a resource
// callback renders it. One-shot: the whole body is already in memory
// (Resource::to_html returns a String, never a stream), so there is no
// reason to hold a persistent z_stream across calls the way #175's
// permessage-deflate streaming will.



namespace webmachine::gzip {

// RFC 1952 2.3.1: magic, CM=8 (deflate), FLG=0, MTIME=0 (unknown - no
// clock this framing can vouch for, same "unknown" as assets.cpp's
// kGzHdr), XFL=0, OS=0xff (unknown). Byte-identical to AssetEntry's
// gz_hdr; kept as this tier's own constant rather than shared, because
// sharing it would tie a per-request path to an asset-tier type for
// ten static bytes that never change.
inline constexpr unsigned char kHeader[10] = {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff};

// Level 1 (Z_BEST_SPEED, #147: dynamic bodies live at the fast end of
// the scale only - zstd -19 / brotli q11 are an asset BUILD's job,
// never a response's). Raw deflate (windowBits -15): no zlib/gzip
// wrapper from zlib itself - the header above and the trailer below
// ARE the wrapper, hand-built the same way assets.cpp's is, so both
// tiers emit the exact same envelope shape around a deflate stream.
//
// False = zlib refused compressing (allocation failure, or `in` at
// or above 4 GiB - avail_in is uint32_t and no resource body comes
// anywhere close). The caller's answer is to serve identity instead:
// compression is an optimization on top of an always-correct fallback,
// never a reason to fail the response (#147: identity is ALWAYS
// available for a dynamic body, so nothing here may 406 or 500).
inline bool compress(const std::string& in, std::string& out) {
  if (in.size() >= std::numeric_limits<uint32_t>::max()) return false;
  z_stream strm{};
  if (deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    return false;
  }
  const unsigned long bound = deflateBound(&strm, static_cast<unsigned long>(in.size()));
  out.assign(reinterpret_cast<const char*>(kHeader), sizeof(kHeader));
  const size_t body_off = out.size();
  out.resize(body_off + bound);
  // zlib's next_in is Bytef* even for input it only reads (the const
  // is missing from the 1995 API, not from the contract).
  strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  strm.avail_in = static_cast<uInt>(in.size());
  strm.next_out = reinterpret_cast<Bytef*>(&out[0]) + body_off;
  strm.avail_out = static_cast<uInt>(bound);
  const int rc = deflate(&strm, Z_FINISH);
  const size_t produced = strm.total_out;
  deflateEnd(&strm);
  // deflateBound sized the buffer for one call to finish the WHOLE
  // input in a single shot; anything but Z_STREAM_END here means
  // zlib itself refused (not "needs another call" - there isn't
  // going to be one).
  if (rc != Z_STREAM_END) return false;
  out.resize(body_off + produced);

  const uint32_t crc = static_cast<uint32_t>(
      crc32_z(0, reinterpret_cast<const Bytef*>(in.data()), in.size()));
  const uint32_t isize = static_cast<uint32_t>(in.size());  // RFC 1952: length mod 2^32
  unsigned char trailer[8];
  trailer[0] = static_cast<unsigned char>(crc);
  trailer[1] = static_cast<unsigned char>(crc >> 8);
  trailer[2] = static_cast<unsigned char>(crc >> 16);
  trailer[3] = static_cast<unsigned char>(crc >> 24);
  trailer[4] = static_cast<unsigned char>(isize);
  trailer[5] = static_cast<unsigned char>(isize >> 8);
  trailer[6] = static_cast<unsigned char>(isize >> 16);
  trailer[7] = static_cast<unsigned char>(isize >> 24);
  out.append(reinterpret_cast<const char*>(trailer), sizeof(trailer));
  return true;
}

}  // namespace webmachine::gzip

// ------------------------------------------------------------------
// Assets out of ONE ZIP file (#170): one fd, one mmap, a table built
// at add_route and never touched again. Only the Central Directory is
// read (its sizes are always right; Local Header sizes may be zeroed
// by data descriptors, flag bit 3) - each entry's local header is
// skipped once at setup, never per request.
//
// THE ZIP METHOD ENCODES THE DELIVERY DECISION: method 8 (deflate) is
// served as Content-Encoding: gzip - a method-8 entry IS a raw deflate
// stream, i.e. exactly the body of a gzip response; the two fields the
// gzip trailer needs (CRC-32, uncompressed size) sit in the Central
// Directory. Method 0 (stored) is served as identity. One field
// compare at runtime - no table, no heuristic, no percentage.
// (History: an old rule said "never infer the coding from the method".
// It held when method 0 was ambiguous - identity OR brotli in a .br
// sibling entry. With ONE entry per file and no siblings, method 0 is
// unambiguously identity, and the inference is exactly right.)
//
// WHY ONLY DEFLATE (user decision, final): the file must survive the
// Windows Explorer - open, read, AND change. Explorer writes deflate
// and cannot be taught stored or zstd, and it cannot keep sibling
// entries in sync. With one deflate-or-stored entry per file, an
// Explorer edit degrades cleanly (a replaced JPEG becomes method 8 and
// ships as gzip: wasteful, correct, fixed by the next build) instead
// of breaking. Zip64 is EXCLUDED, not postponed - Explorer's Zip64
// support is historically bad: < 65535 entries and < 4 GB is a
// requirement, refused by name at setup.
//
// Path traversal is structurally impossible, not filtered: a request
// can only name what the table holds. No ..-parsing, no realpath, no
// CVE class.




namespace webmachine {

// The extension -> media type table, read ONCE at setup and never on a
// request path. It comes off the MACHINE: a media-type database is
// something the operator installs and curates, and a table kept in
// this source could only ever be a worse, staler copy of it.
//
// Sources, first that exists wins:
//   1. the path the operator named ([server].mime_types, --mime-types)
//   2. /etc/mime.types            Debian media-types, Fedora/Arch mailcap
//   3. /etc/apache2/mime.types, /etc/httpd/conf/mime.types,
//      /usr/local/etc/mime.types                 Apache per distro, BSD
//   4. /usr/share/mime/globs2                        shared-mime-info
//   5. the list compiled in (share/mime.types, Apache httpd's own)
//
// Two formats, because there are two: "type ext ext ..." for 1-3 and
// 5, "weight:type:*.ext" for globs2. nginx's block form stays out -
// an operator who has one names it through source 1.
class MimeDb {
 public:
  // A path the OPERATOR named and that cannot be read is a refusal,
  // not a step down the list: they named it on purpose. Everything
  // else falls through, and source() then says what answered.
  bool load(const char* configured, char* err, size_t errlen);
  const std::string& source() const { return source_; }
  size_t size() const { return by_ext_.size(); }
  // Never null. RFC 9110 8.3: a generic claim is only worse than no
  // claim when it lies, and octet-stream never does.
  const char* type_of(const std::string& name) const;

 private:
  void take(const char* type, size_t tlen, const char* ext, size_t elen);
  void parse_types(const char* p, const char* end);
  void parse_globs2(const char* p, const char* end);

  // Sorted by extension, binary-searched - the same shape the asset
  // table uses, and setup is its only reader.
  std::vector<std::pair<std::string, std::string>> by_ext_;
  std::string source_;
};

// Everything about one served entry, computed at setup. `data` points
// into the mapping, past the local header - the deflate (or stored)
// bytes the wire carries untouched.
struct AssetEntry {
  std::string name;  // the lookup key: the archive name, no leading slash
  const char* data = nullptr;
  size_t comp_size = 0;
  size_t uncomp_size = 0;
  uint32_t crc = 0;
  bool deflated = false;  // ZIP method 8; false = stored (method 0)
  bool lm_valid = false;  // a DOS date of 0 has no meaning to serve
  // ETag = the Central Directory's CRC-32, quoted. It names the
  // UNCOMPRESSED data, and because exactly ONE representation is ever
  // served per entry, no collision across coding boundaries is
  // possible - no suffix needed (RFC 9110 §8.8.3.3).
  char etag[10] = {};  // "xxxxxxxx"
  char lm[http::kDateLen] = {};  // Last-Modified, IMF-fixdate
  std::string ctype;  // from the extension, decided once at setup

  // Prebuilt h1 header sections (status line through the blank line),
  // date patched LAZILY at answer time - a per-second sweep over
  // thousands of entries would be work nobody asked for; an entry
  // nobody requests is never patched. Indexed by Variant.
  struct Resp {
    std::string bytes;
    size_t date_off = 0;
    time_t sec = 0;  // the second the date bytes belong to
  };
  Resp h200[3];
  Resp h304[3];

  // gzip framing around the deflate bytes (method 8 only). The header
  // is constant ONLY because MTIME=0 and OS=0xff - both legal
  // "unknown" per RFC 1952; a real mtime would make it per-entry.
  unsigned char gz_hdr[10] = {};
  unsigned char gz_trailer[8] = {};

  // h2 header blocks (never-indexed HPACK), built by Http1 at setup -
  // the HPACK spelling lives in http2.cpp, not here. Date-free: the
  // date rides the encoder lane per response.
  std::string h2_200;
  std::string h2_304;
};

class Assets {
 public:
  // RFC 9112 §9.3 connection spellings, same shape as Http1's
  // Variants: a persistent 1.1 response carries no Connection header,
  // a persistent 1.0 echoes keep-alive, anything closing spells close.
  // kKeep is 1.0-ONLY and only on request: RFC 9112 9.3 makes 1.1
  // persistent by default (the header would be noise) and C.2.2 is the
  // echo rule for 1.0. http1.cpp's picker is where that is decided.
  enum Variant : uint8_t { kPlain = 0, kKeep = 1, kClose = 2 };
  // The three spellings, ONCE, indexed by the enum that names them -
  // they used to stand twice in assets.cpp (prebuilt heads and a
  // switch for per-request heads), which is how two spellings of one
  // table drift apart (#146 paid for that lesson already).
  static constexpr const char* kConn[3] = {"", "Connection: keep-alive\r\n",
                                           "Connection: close\r\n"};

  Assets() = default;
  ~Assets();
  Assets(const Assets&) = delete;
  Assets& operator=(const Assets&) = delete;

  // Parse + map + prebuild. False leaves the named refusal in err -
  // Zip64, encryption, a method that is neither 0 nor 8, a truncated
  // directory: all name themselves, nothing degrades silently.
  bool open(const char* zip_path, const MimeDb& mime, char* err, size_t errlen);

  // path is the request-target (origin-form): the query is stripped,
  // the leading slash dropped, and the rest must equal a table name
  // byte for byte (no percent-decoding: entries are named by their
  // table row, not by an escape grammar). Null = not an asset; the
  // caller falls through to its app resource.
  AssetEntry* find(const char* path, size_t len);

  // The asset tier's whole decision, in the graph's own order (conneg
  // before preconditions, C..F before G..):
  //   405 anything but GET/HEAD (501 for methods the tree cannot name)
  //   406 method-8 entry, Accept-Encoding present, gzip not acceptable
  //   412 If-Match present and the strong comparison fails
  //   304 If-None-Match matches (weak comparison)
  //   200 otherwise
  // The 406 deviates from a SHOULD by name: §12.5.3 says a server
  // should fall back to no coding - assuming it CAN produce an
  // uncompressed representation. This tree deliberately cannot (no
  // inflate anywhere); §15.5.7 sanctions the refusal.
  uint16_t verdict(const AssetEntry& e, flow::Method m, const flow::ReqFacts& f,
                   const http::ReqValues& vals) const;

  // Append the h1 HEADER SECTION for a verdict this tier owns (200,
  // 304, 405, 406) - never body bytes: delivery is the caller's (#168,
  // it owns the budget and the transfer state). 412/501 stay with the
  // caller's shared status store - they carry nothing asset-specific.
  void answer_head(AssetEntry& e, uint16_t status, Variant v, const char* date, time_t sec,
                   std::string& sink);

  // Ranged heads (#148) are built per request - the rare path, and
  // they carry three request-dependent numbers no prebuild can hold.
  // The window [first, last] counts octets of the WIRE body
  // (wire_len), i.e. the selected representation's encoded bytes.
  void answer_206_head(const AssetEntry& e, Variant v, size_t first, size_t last,
                       const char* date, std::string& sink);
  void answer_416_head(const AssetEntry& e, Variant v, const char* date, std::string& sink);

  // The wire body and the ONE place that knows its shape: gzip header
  // + deflate bytes + trailer for method 8, the stored bytes alone for
  // method 0. Both protocols go through here - h1 chunks, h2 frames,
  // parked continuations - so the segment arithmetic exists once.
  static size_t wire_len(const AssetEntry& e) {
    return e.deflated ? e.comp_size + 18 : e.comp_size;
  }
  // POINTERS, not bytes: [off, off+n) of the wire body as up to three
  // iovecs - the constant gzip header, the deflate stream WHERE IT
  // LIES IN THE MAPPING, the trailer. Nothing is copied; the kernel
  // reads the mapping directly on send. Returns how many iovecs were
  // filled. This is what #168 means by "a source delivers a plan": the
  // one copy that remains is the kernel's, into the socket buffer.
  static unsigned wire_iov(const AssetEntry& e, size_t off, size_t n, struct iovec* iov);
  // The copying form, kept for the paths that must own their bytes:
  // h2 DATA frames interleave with other streams' frames in one sink,
  // so their payload cannot be a pointer that outlives the round.
  static void copy_wire(const AssetEntry& e, size_t off, size_t n, std::string& sink);

  std::vector<AssetEntry>& entries() { return entries_; }

 private:
  static void patch_date(AssetEntry::Resp& r, const char* date, time_t sec);

  const char* map_ = nullptr;
  size_t map_len_ = 0;
  std::vector<AssetEntry> entries_;  // sorted by name; find binary-searches
  // Shared refusal heads (405 with Allow: GET, HEAD / 406 with Vary),
  // one triple each, date patched lazily like the entry heads.
  AssetEntry::Resp s405_[3];
  AssetEntry::Resp s406_[3];
};

}  // namespace webmachine

// ------------------------------------------------------------------
// HTTP/2 connection state and wire helpers (RFC 9113). One H2State per
// connection that spoke the client preface, allocated THEN and never
// before - eager per-connection objects measured -12% throughput /
// +58% p99 at 7000 idle connections on the old tree, so an h1
// connection carries one null pointer and nothing else.
//
// Only the HPACK codec is foreign (ls-hpack, see mrbgem.rake); the
// frame and stream machinery is this tree's own, driven from
// http2.cpp. Priority trees are deprecated in RFC 9113 and absent
// here; so is server push (8.4 forbids the client, nothing here wants
// the server side).


#include "lshpack.h"

namespace webmachine {

// Frame types (RFC 9113 6).
enum : uint8_t {
  kH2Data = 0x0,
  kH2Headers = 0x1,
  kH2Priority = 0x2,
  kH2RstStream = 0x3,
  kH2Settings = 0x4,
  kH2PushPromise = 0x5,
  kH2Ping = 0x6,
  kH2Goaway = 0x7,
  kH2WindowUpdate = 0x8,
  kH2Continuation = 0x9,
};

// Frame flags. ACK shares the END_STREAM bit on purpose (the spec's).
enum : uint8_t {
  kH2FlagEndStream = 0x1,
  kH2FlagAck = 0x1,
  kH2FlagEndHeaders = 0x4,
  kH2FlagPadded = 0x8,
  kH2FlagPriority = 0x20,
};

// Error codes (RFC 9113 7).
enum : uint32_t {
  kH2NoError = 0x0,
  kH2ProtocolError = 0x1,
  kH2InternalError = 0x2,
  kH2FlowControlError = 0x3,
  kH2StreamClosed = 0x5,
  kH2FrameSizeError = 0x6,
  kH2RefusedStream = 0x7,
  kH2CompressionError = 0x9,
  kH2EnhanceYourCalm = 0xb,
};

// Settings identifiers (RFC 9113 6.5.2).
enum : uint16_t {
  kH2SettingsHeaderTableSize = 0x1,
  kH2SettingsEnablePush = 0x2,
  kH2SettingsMaxConcurrentStreams = 0x3,
  kH2SettingsInitialWindowSize = 0x4,
  kH2SettingsMaxFrameSize = 0x5,
};

// The client connection preface (RFC 9113 3.4).
inline constexpr char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr size_t kH2PrefaceLen = 24;
// The ANNOUNCEMENT half: no HTTP/1 request begins with these sixteen
// bytes, so a connection that got this far has said "h2" whether or
// not it finishes the sentence. What follows the announcement can
// therefore be answered as h2 - with a GOAWAY - instead of with a
// status line the peer is not reading (RFC 9113 3.5, h2spec 3.5/2).
inline constexpr size_t kH2PrefaceAnnounce = 18;

inline constexpr size_t kH2FrameHeaderLen = 9;
// Ours, and also the floor every peer must accept (RFC 9113 4.2).
inline constexpr uint32_t kH2MaxFrameSize = 16384;
inline constexpr int64_t kH2DefaultWindow = 65535;
inline constexpr uint32_t kH2MaxConcurrentStreams = 256;
inline constexpr int64_t kH2WindowCeiling = 0x7fffffff;

inline void h2_put_frame_header(unsigned char* p, uint32_t len, uint8_t type,
                                uint8_t flags, uint32_t stream) {
  p[0] = static_cast<unsigned char>(len >> 16);
  p[1] = static_cast<unsigned char>(len >> 8);
  p[2] = static_cast<unsigned char>(len);
  p[3] = type;
  p[4] = flags;
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

// Patches the 4 stream-id bytes h2_put_frame_header wrote at a fixed
// offset (5) within an ALREADY-EMITTED frame header - the same trick
// http1's on_tick uses for its date_off, applied to stream id instead
// of date. p must point at byte 0 of that 9-byte frame header.
inline void h2_patch_stream_id(unsigned char* p, uint32_t stream) {
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

inline uint32_t h2_u24(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}
inline uint32_t h2_u32(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
inline uint32_t h2_u31(const unsigned char* p) { return h2_u32(p) & 0x7fffffff; }
inline uint16_t h2_u16(const unsigned char* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// One stream the connection still needs to remember. A stream answered
// in full inside its own dispatch never appears here. Request bodies
// are COUNTED and discarded, exactly the h1 tier (no consumer until
// the POST/PUT tier delivers them) - what survives until END_STREAM is
// the facts vector, not the bytes.
struct AssetEntry;  // assets.hpp owns it (#170)

struct H2Stream {
  uint32_t id = 0;
  int64_t send_window = kH2DefaultWindow;
  size_t body_len = 0;  // received DATA payload, counted against kMaxBody
  // RFC 9113 8.1.2.6: a content-length that disagrees with the DATA
  // actually sent makes the request malformed. Remembered here because
  // the disagreement can only be seen at END_STREAM.
  size_t content_length = 0;
  bool have_content_length = false;
  // Response DATA the peer's window refused; flushed on WINDOW_UPDATE.
  std::string pending;
  flow::ReqFacts facts;  // decoded at HEADERS, dispatched at END_STREAM
  // An asset request resolves at dispatch - the header VALUES it
  // negotiates with die with the decode buffer - so what parks here is
  // the entry and the finished verdict, never a value pointer.
  const AssetEntry* asset = nullptr;
  uint16_t asset_status = 0;
  // The answer's window into the wire body (#148): the full body for
  // a 200, the satisfied range for a 206. Resolved at dispatch like
  // the verdict - the Range/If-Range values die with the decode
  // buffer.
  size_t asset_off = 0;
  size_t asset_end = 0;
  // A parked DELIVERY (#168): no byte lies in the park, an offset
  // does. src_off walks [0, src_len) over Assets::copy_wire's virtual
  // wire body; `pending` (bytes) remains for dynamic bodies, which
  // have no durable backing to point into.
  const AssetEntry* src = nullptr;
  size_t src_off = 0;
  size_t src_len = 0;
  // The router's verdict for this stream (#116), resolved at HEADERS
  // like the asset verdict and for the same reason: the :path bytes
  // die with the decode buffer. kNoRoute = a miss, answered 404.
  uint16_t route = 0;
  // A COPY of the :path value, for the same reason spelled the other
  // way round (#116 slice 4): a request that parks answers after its
  // decode buffer is gone, so a request object built then has nothing
  // to point at unless the bytes were kept. Only a stream that PARKS
  // pays this - a request answered inside its own dispatch borrows the
  // live bytes and copies nothing.
  std::string target;
  bool head_only = false;
  bool headers_done = false;
  bool half_closed_remote = false;
};

struct H2State {
  // Two lanes on the sending side: what never changes is PRECOMPUTED
  // as never-indexed blocks (Http1::h2_build_block - status, date
  // patched per second, konst content-type, allow) and costs a
  // memcpy; what is dynamic per request goes through ls-hpack's
  // encoder (Http1::h2_enc_field). Never-indexed literals touch no
  // table state on either side, so the lanes interleave freely in one
  // header block.
  struct lshpack_enc enc;
  struct lshpack_dec dec;

  // What the PEER may still receive - connection-level, debited by
  // every DATA payload byte sent, credited by their WINDOW_UPDATEs.
  int64_t send_window = kH2DefaultWindow;
  int64_t peer_initial_window = kH2DefaultWindow;
  uint32_t peer_max_frame = kH2MaxFrameSize;
  uint32_t last_stream = 0;  // highest stream id seen, for GOAWAY
  // The highest client-initiated id this connection ever ACCEPTED.
  // With the stream table it is the whole state machine (RFC 9113
  // 5.1): an id above it was never used and the stream is IDLE, an id
  // at or below it that is no longer in the table is CLOSED, and the
  // two earn different errors. Keeping the number instead of the dead
  // streams is what makes that free.
  uint32_t highest_opened = 0;
  // Where the next drain round starts walking the stream table. The
  // round is bounded (it stops when the plan is full), so without a
  // moving start the first parked stream would take every round until
  // it finished and the last one would wait out all the others. A
  // hint, not an index: close_stream reorders the table under it, and
  // a stale value only costs a different starting point.
  size_t flush_cursor = 0;
  bool goaway_sent = false;
  bool goaway_recv = false;  // the peer is done; finish and close

  // A header block split over HEADERS + CONTINUATION accumulates here;
  // frag_stream says whose it is, END_STREAM travels in frag_flags.
  std::string frag;
  uint32_t frag_stream = 0;
  uint8_t frag_flags = 0;
  bool frag_active = false;

  // Decoded header bytes for the request being dispatched. Reused, so
  // its capacity survives; facts are extracted before the next decode.
  std::string hdrbuf;

  std::vector<H2Stream> streams;

  // The response cache: one slot, deliberately not one per status -
  // the -12%/+58% eager-per-connection-object cost above is exactly
  // why this stays small. Homogeneous traffic (the common case) gets
  // the full win; a status change just falls back to rebuilding it
  // fresh, same cost as before this cache existed, never wrong.
  //
  // bytes holds a whole HEADERS frame (header + h2_store_ block +
  // encoded date) and, when has_data, the whole DATA frame right
  // behind it - so the common answer is ONE append of one contiguous
  // buffer, the way h1 answers. head_len says where the HEADERS frame
  // ends, which is both the second frame's patch point and the length
  // to append when the body must not ride along (HEAD, a bodyless
  // status, or a window too small for it).
  //
  // Every byte in here is fixed except two 4-byte stream ids and one
  // flags byte, all at offsets h2_put_frame_header defines. Valid
  // only while status/sec still match.
  struct {
    std::string bytes;
    size_t head_len = 0;
    bool has_data = false;
    uint16_t status = 0;
    // Which ROUTE's block is cached: the same status means different
    // bytes for different resources (content-type, allow), so the
    // route joins the key. One more compare on a path that already
    // compares two.
    uint16_t route = 0xffff;
    time_t sec = 0;
  } head_cache;

  H2State() {
    lshpack_enc_init(&enc);
    lshpack_dec_init(&dec);
  }
  ~H2State() {
    lshpack_enc_cleanup(&enc);
    lshpack_dec_cleanup(&dec);
  }
  H2State(const H2State&) = delete;
  H2State& operator=(const H2State&) = delete;

  H2Stream* find(uint32_t id) {
    for (H2Stream& st : streams)
      if (st.id == id) return &st;
    return nullptr;
  }
  H2Stream& open(uint32_t id) {
    if (H2Stream* st = find(id)) return *st;
    streams.emplace_back();
    H2Stream& st = streams.back();
    st.id = id;
    st.send_window = peer_initial_window;
    return st;
  }
  void close_stream(uint32_t id) {
    for (size_t i = 0; i < streams.size(); i++) {
      if (streams[i].id == id) {
        streams[i] = std::move(streams.back());
        streams.pop_back();
        return;
      }
    }
  }
};

}  // namespace webmachine

// ------------------------------------------------------------------
// permessage-deflate (#175 round two, RFC 7692): the NEGOTIATION and
// the CODEC, and nothing else. No mruby, no connection, no IO - the
// same cut websocket.hpp makes for the framing, so both halves can be
// driven from a test binary before a socket exists.
//
// WHY THE SYSTEM zlib AND NOT libdeflate (which this tree already
// carries for #170's zip reader): 7692 is a STREAM. A message is
// compressed with Z_SYNC_FLUSH and the LZ77 window is carried into the
// next one (7.1.1, "context takeover"), so the compressor's state
// outlives every single call. libdeflate's whole-buffer API cannot
// express that at all - it is not slower here, it is unable. zlib's
// z_stream is, and libz.so.1 is on every server distribution (see
// mrbgem.rake for the standing rule).
//
// WHAT IT COSTS, per connection, said in bytes because that is the
// number that decides the default: zlib's own arithmetic (deflate.c)
// is (1 << (windowBits+2)) + (1 << (memLevel+9)) for the compressor -
// 128 KiB + 128 KiB at the defaults - plus (1 << windowBits) + state
// for the decompressor, about 40 KiB. Call it 296 KiB PER PEER, on a
// tree whose connection capacity is derived in the tens of thousands
// (#169). That is why the extension is OPT-IN per route
// (WebsocketResource.permessage_deflate?, default false) and why the
// streams are built LAZILY, on the first message that actually needs
// one: h2.hpp already carries the measurement that eager
// per-connection objects cost -12% throughput and +58% p99 at 7000
// idle connections, and this object is two orders of magnitude bigger
// than the one that did that.



namespace webmachine {
namespace wsdeflate {

// THE SMALLEST WINDOW A RAW DEFLATE STREAM CAN HAVE, and it is not
// 8: deflateInit2 checks `windowBits == 8 && wrap != 1` and answers
// Z_STREAM_ERROR, because the 256-byte window has a bug zlib never
// fixed. 7692 lets a client name 8 anyway (7.1.2.1: 8 to 15
// inclusive), and this one number answers both directions of that.
//
// server_max_window_bits=8 is DECLINED by name rather than answered
// with 9 - a response naming a larger window than the offer is what
// 7.1.2.1 forbids, and a response naming 8 while compressing with 9
// would hand the peer a stream its inflater cannot follow.
//
// client_max_window_bits=8 is accepted and echoed, and the
// DECOMPRESSOR built one bit larger: the client's zlib cannot produce
// an 8-bit window either, so 9 is what will actually arrive.
inline constexpr uint8_t kMinRawWindowBits = 9;

// RFC 7692 7.2.1 step 4 / 7.2.2 step 1: a Z_SYNC_FLUSH ends the
// deflate stream with an empty stored block, and the four bytes that
// spells are removed by the sender and put back by the receiver. They
// are not payload; they are the frame boundary the extension does not
// need to repeat.
inline constexpr unsigned char kSyncTail[4] = {0x00, 0x00, 0xff, 0xff};

// What one negotiation settled on. `on` false means every other field
// is meaningless: this connection speaks plain RFC 6455.
struct Params {
  bool on = false;
  bool server_no_context_takeover = false;
  bool client_no_context_takeover = false;
  uint8_t server_max_window_bits = 15;  // what THIS side compresses with
  uint8_t client_max_window_bits = 15;  // what the peer compresses with
};

namespace detail {

constexpr bool is_ows(char c) { return c == ' ' || c == '\t'; }

// RFC 9110 5.6.2's token, which is what 7692 4.2's extension-param
// names and unquoted values are.
constexpr bool is_tchar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
         c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' ||
         c == '~';
}

inline bool ci_eq(const char* s, size_t n, const char* lit, size_t litn) {
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// 8..15 with no leading zeroes (7.1.2.1 says so in as many words), so
// "08" and "015" are refusals and not 8 and 15.
inline bool window_bits(const char* v, size_t n, uint8_t& out) {
  if (n == 0 || n > 2) return false;
  if (v[0] == '0') return false;
  unsigned x = 0;
  for (size_t i = 0; i < n; i++) {
    if (v[i] < '0' || v[i] > '9') return false;
    x = x * 10 + static_cast<unsigned>(v[i] - '0');
  }
  if (x < 8 || x > 15) return false;
  out = static_cast<uint8_t>(x);
  return true;
}

}  // namespace detail

// ONE Sec-WebSocket-Extensions field value - a comma-separated offer
// list (RFC 7692 4.2, RFC 9110 5.6.1) - answered with the FIRST
// permessage-deflate offer this endpoint can accept. `answer` gets the
// response field value; `out` gets what the codec must then do.
//
// Declining is never an error: 7692 5.1 lets a server ignore an offer
// it does not want, and the connection is then a perfectly good plain
// websocket. So this returns false for "nothing here", never for "this
// handshake is bad" - the ONE thing that could fail a handshake is a
// malformed header, and a malformed extension header is indistinguish-
// able from an extension we do not offer.
inline bool negotiate(const char* v, size_t len, Params& out, std::string& answer) {
  size_t i = 0;
  while (i < len) {
    // ---- one offer, up to the next top-level comma
    while (i < len && (detail::is_ows(v[i]) || v[i] == ',')) i++;
    const size_t name_at = i;
    while (i < len && detail::is_tchar(v[i])) i++;
    const size_t name_len = i - name_at;
    bool ok = detail::ci_eq(v + name_at, name_len, "permessage-deflate", 18);

    Params p;
    p.on = true;
    bool seen_snct = false, seen_cnct = false, seen_smwb = false, seen_cmwb = false;
    bool echo_cmwb = false;

    while (true) {
      while (i < len && detail::is_ows(v[i])) i++;
      if (i >= len || v[i] != ';') break;
      i++;  // the ';'
      while (i < len && detail::is_ows(v[i])) i++;
      const size_t pn_at = i;
      while (i < len && detail::is_tchar(v[i])) i++;
      const size_t pn_len = i - pn_at;
      while (i < len && detail::is_ows(v[i])) i++;
      const char* pv = nullptr;
      size_t pv_len = 0;
      bool have_value = false;
      if (i < len && v[i] == '=') {
        i++;
        while (i < len && detail::is_ows(v[i])) i++;
        have_value = true;
        if (i < len && v[i] == '"') {
          // 9110 5.6.4: a quoted-string. 7692's own values are all
          // tokens, but a client is allowed to quote them and some do.
          i++;
          pv = v + i;
          while (i < len && v[i] != '"') {
            if (v[i] == '\\' && i + 1 < len) i++;  // quoted-pair
            i++;
          }
          pv_len = static_cast<size_t>(v + i - pv);
          if (i < len) i++;  // the closing quote
        } else {
          pv = v + i;
          while (i < len && detail::is_tchar(v[i])) i++;
          pv_len = static_cast<size_t>(v + i - pv);
        }
      }
      if (!ok) continue;  // an offer already refused is only being skipped past

      // 7692 7.1: an extension parameter this endpoint does not know,
      // a value where none belongs, or the same parameter twice makes
      // the OFFER unacceptable - not the handshake. The next offer in
      // the list gets its turn.
      if (detail::ci_eq(v + pn_at, pn_len, "server_no_context_takeover", 26)) {
        if (seen_snct || have_value) { ok = false; continue; }
        seen_snct = true;
        p.server_no_context_takeover = true;
      } else if (detail::ci_eq(v + pn_at, pn_len, "client_no_context_takeover", 26)) {
        if (seen_cnct || have_value) { ok = false; continue; }
        seen_cnct = true;
        p.client_no_context_takeover = true;
      } else if (detail::ci_eq(v + pn_at, pn_len, "server_max_window_bits", 22)) {
        // 7.1.2.1: in an OFFER this parameter always carries a value.
        uint8_t b = 0;
        if (seen_smwb || !have_value || !detail::window_bits(pv, pv_len, b) ||
            b < kMinRawWindowBits) {
          ok = false;
          continue;
        }
        seen_smwb = true;
        p.server_max_window_bits = b;
      } else if (detail::ci_eq(v + pn_at, pn_len, "client_max_window_bits", 22)) {
        // 7.1.2.2: with or without a value. Without one it says only
        // that the client would UNDERSTAND the parameter in the
        // response - the client still uses 15 unless the response
        // names something smaller, and this endpoint names nothing.
        // With one, the value is what the client would rather use, so
        // it is echoed and the decompressor is built that small.
        if (seen_cmwb) { ok = false; continue; }
        seen_cmwb = true;
        if (have_value) {
          uint8_t b = 0;
          if (!detail::window_bits(pv, pv_len, b)) { ok = false; continue; }
          p.client_max_window_bits = b;
          echo_cmwb = true;
        }
      } else {
        ok = false;  // 7.1: an unknown parameter
      }
    }

    if (ok) {
      out = p;
      answer.assign("permessage-deflate");
      // Only what was OFFERED goes back (7.1.2.1: a response value must
      // not exceed the offer; 7.1.2.2: client_max_window_bits may not
      // appear at all unless the client asked for it). The two
      // no_context_takeover parameters are echoed as confirmation -
      // the client promised, and this endpoint says it heard.
      if (p.server_no_context_takeover) answer.append("; server_no_context_takeover");
      if (p.client_no_context_takeover) answer.append("; client_no_context_takeover");
      if (seen_smwb) {
        answer.append("; server_max_window_bits=")
            .append(std::to_string(static_cast<unsigned>(p.server_max_window_bits)));
      }
      if (echo_cmwb) {
        answer.append("; client_max_window_bits=")
            .append(std::to_string(static_cast<unsigned>(p.client_max_window_bits)));
      }
      return true;
    }
    // Past this offer's own comma, whatever was left of it.
    while (i < len && v[i] != ',') i++;
  }
  return false;
}

// The two zlib streams of ONE connection, built on first use and not
// before (see the header: 296 KiB is not a thing to hand out at
// accept). Neither is a value type - a z_stream holds pointers into
// its own allocation - so this neither copies nor moves.
class Codec {
 public:
  Codec() = default;
  Codec(const Codec&) = delete;
  Codec& operator=(const Codec&) = delete;
  ~Codec() {
    if (inf_on_) inflateEnd(&inf_);
    if (def_on_) deflateEnd(&def_);
  }

  void configure(const Params& p) { p_ = p; }
  const Params& params() const { return p_; }

  // ---- receiving: 7692 7.2.2

  // Payload bytes of a compressed message, as they arrive. `sink` is
  // called with each run of decompressed bytes and answers false when
  // the message may not grow any further (max_message) - which is the
  // ONLY guard against a decompression bomb, and the reason the
  // compressed side is deliberately not bounded: a peer may spend all
  // the bandwidth it likes, it may not choose how much of THIS
  // process's heap the result takes.
  //   0 = fed, -1 = not a DEFLATE stream, -2 = the sink said stop
  template <class Sink>
  int inflate_some(const char* in, size_t n, Sink&& sink) {
    if (!inflate_ready()) return -1;
    inf_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
    inf_.avail_in = static_cast<uInt>(n);
    return pump(sink);
  }

  // The message ended: 7.2.2 step 1 puts the four bytes back that the
  // sender removed, and what falls out of them is the tail of the
  // message.
  template <class Sink>
  int inflate_finish(Sink&& sink) {
    if (!inflate_ready()) return -1;
    inf_.next_in = const_cast<Bytef*>(kSyncTail);
    inf_.avail_in = sizeof(kSyncTail);
    const int rc = pump(sink);
    if (rc != 0) return rc;
    // 7.1.1.1: without context takeover the peer starts every message
    // from an empty window, so this side must too. A stream that ended
    // (the peer sent a BFINAL block) is reset either way - nothing can
    // follow a finished deflate stream.
    if (p_.client_no_context_takeover || inf_ended_) {
      inflateReset(&inf_);
      inf_ended_ = false;
    }
    return 0;
  }

  // ---- sending: 7692 7.2.1

  // One whole message compressed into `out`, ready to be the payload
  // of a frame with RSV1 set. False = zlib refused (an allocation, or
  // a stream that broke); the caller's answer is to send the message
  // uncompressed, which 6455 always allows and 7692 6 explicitly does
  // - and this codec then never compresses again on this connection,
  // because a half-fed context is a stream the peer can no longer
  // follow.
  bool compress(const char* in, size_t n, std::string& out) {
    // avail_in is a uInt and has been since 1995. No route's
    // max_message comes near 4 GiB, and the one that did would get a
    // silently truncated message rather than a refusal - so it is a
    // refusal, and the caller sends the thing uncompressed.
    if (n > std::numeric_limits<uInt>::max()) return false;
    if (def_broken_ || !deflate_ready()) return false;
    out.clear();
    def_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
    def_.avail_in = static_cast<uInt>(n);
    unsigned char buf[8192];
    for (;;) {
      def_.next_out = buf;
      def_.avail_out = sizeof(buf);
      const int rc = deflate(&def_, Z_SYNC_FLUSH);
      if (rc != Z_OK && rc != Z_BUF_ERROR) {
        def_broken_ = true;
        return false;
      }
      out.append(reinterpret_cast<const char*>(buf), sizeof(buf) - def_.avail_out);
      // Z_SYNC_FLUSH is done when it stopped needing room: zlib's own
      // "avail_out != 0 means the flush completed" (deflate.c).
      if (def_.avail_out != 0) break;
    }
    // 7.2.1 step 4: drop the 00 00 FF FF the flush just wrote. An
    // EMPTY message flushes to exactly those four plus one byte of
    // empty-block header, so what is left is one byte - which is the
    // shortest legal compressed payload and not a bug.
    if (out.size() < sizeof(kSyncTail) ||
        std::memcmp(out.data() + out.size() - sizeof(kSyncTail), kSyncTail,
                    sizeof(kSyncTail)) != 0) {
      def_broken_ = true;
      return false;
    }
    out.resize(out.size() - sizeof(kSyncTail));
    // 7.1.1.1: the client asked this side to start every message from
    // an empty window, so the window goes away between messages. It is
    // the same z_stream - the 256 KiB stays; what resets is the
    // history the peer's inflater is allowed to assume.
    if (p_.server_no_context_takeover) deflateReset(&def_);
    return true;
  }

 private:
  bool inflate_ready() {
    if (inf_on_) return true;
    // Raw deflate (a negative windowBits): 7692 carries no zlib or
    // gzip wrapper, the frame IS the envelope. The window is what the
    // negotiation said the peer would use: at 9 bits that is 512 bytes
    // instead of the 32 KiB a full one costs, per connection, and a
    // decompressor may always be LARGER than the compressor was, never
    // smaller.
    //
    // Never below 9, though, and the reason is the same zlib rule that
    // makes this side decline server_max_window_bits=8: no zlib
    // compressor can produce a raw 8-bit window, so a client that
    // asked for 8 will be compressing with 9 whatever it meant to say.
    // One bit larger than promised can only ever be right; one bit
    // smaller would fail a stream that is perfectly legal.
    const int bits = p_.client_max_window_bits < kMinRawWindowBits
                         ? kMinRawWindowBits
                         : p_.client_max_window_bits;
    if (inflateInit2(&inf_, -bits) != Z_OK) return false;
    inf_on_ = true;
    return true;
  }

  bool deflate_ready() {
    if (def_on_) return true;
    // Z_BEST_SPEED, the same end of the scale gzip.hpp's dynamic
    // bodies live at (#147: a response compresses at request time, so
    // it compresses fast). It costs less here than it does there,
    // because context takeover means the dictionary - not the search
    // effort - is what makes a chatty connection's messages small.
    // memLevel 8 is zlib's own default and stays it: deviating is a
    // ratio-against-memory trade, and this tree does not publish those
    // without a measurement on real hardware.
    if (deflateInit2(&def_, Z_BEST_SPEED, Z_DEFLATED,
                     -static_cast<int>(p_.server_max_window_bits), 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
      def_broken_ = true;
      return false;
    }
    def_on_ = true;
    return true;
  }

  template <class Sink>
  int pump(Sink& sink) {
    unsigned char buf[8192];
    for (;;) {
      inf_.next_out = buf;
      inf_.avail_out = sizeof(buf);
      const int rc = inflate(&inf_, Z_NO_FLUSH);
      if (rc == Z_STREAM_END) inf_ended_ = true;
      else if (rc != Z_OK && rc != Z_BUF_ERROR) return -1;
      const size_t got = sizeof(buf) - inf_.avail_out;
      if (got != 0 && !sink(reinterpret_cast<const char*>(buf), got)) return -2;
      if (inf_.avail_out != 0) return 0;  // zlib had room left: it is done
    }
  }

  Params p_;
  z_stream inf_{};
  z_stream def_{};
  bool inf_on_ = false;
  bool def_on_ = false;
  bool def_broken_ = false;
  bool inf_ended_ = false;
};

}  // namespace wsdeflate
}  // namespace webmachine

// ------------------------------------------------------------------
// WebSocket, round one's second half (#175): a connection that has
// stopped being HTTP. src/websocket.hpp is the protocol (bytes in,
// bytes out, no state); this is the part that holds a peer - message
// assembly, the control-frame duties RFC 6455 puts on an endpoint, and
// the resource the route named.
//
// THE SURFACE (Nutzer-Entscheid 2026-08-22): a websocket route names a
// Webmachine::WebsocketResource, and that class stands on its OWN -
// it is NOT a Webmachine::Resource. Almost nothing of HTTP survives
// the upgrade: there is no response, no status, no flow, no content
// negotiation. What survives is the handshake's HEAD, so that is the
// one thing a websocket resource can ask for (`request`, headers and
// the route's own bindings included). A base class that inherited the
// flow's would have promised all the rest.
//
// It is instantiated ONCE PER CONNECTION (#181) and then FED -
// methods, no block, no proc:
//
//     class Echo < Webmachine::WebsocketResource
//       def initialize                  # optional - the CONNECT hook
//         # This object is THIS peer's, so ivars set here live for the
//         # whole connection. `request` is live too - the handshake's
//         # head: the subprotocol, an Origin check, a token in the
//         # query are decided from it. nil accepts; a String accepts
//         # AND is the Sec-WebSocket-Protocol answer; a Symbol refuses
//         # the upgrade with an HTTP status.
//       end
//
//       def on_data(data, binary)       # required
//         data                          # a String goes back to the client
//       end
//
//       def on_close(code, reason)      # optional
//       end
//     end
//
// Every callback's arity is read ONCE at fold: `def on_data(data)`
// and `def on_data(data, binary)` are both called correctly, and
// nothing is passed that the method did not ask for.
//
// PING AND PONG ARE NOT AN API (Nutzer-Entscheid): a ping is answered
// with a pong here, in C, because RFC 6455 5.5.2 makes that the
// endpoint's duty and not an application decision; an incoming pong is
// silent. A resource never sees either.
//
// Three more konst answers, asked once at fold and free per message:
//
//     def self.max_message = 8 * 1024 * 1024   # default 64 KiB
//     def self.validate_text? = false          # default true
//     def self.permessage_deflate? = true      # default false
//
// validate_text? off means this endpoint stops checking incoming TEXT
// messages against RFC 6455 8.1 - faster on a link whose payloads are
// known good, and a peer sending broken text then gets an answer
// instead of the 1007 the RFC asks for.
//
// permessage_deflate? on means this route ACCEPTS RFC 7692 when a
// client offers it. Off by default, and the default is the honest one:
// the extension costs about 296 KiB of zlib per compressing peer
// (wsdeflate.hpp does the arithmetic), on a tree whose connection
// capacity is derived in the tens of thousands. A route that talks to
// browsers over a metered link wants it; a route fanning out to
// thousands of idle sockets does not, and neither should have to find
// that out from a memory graph. Nothing else about the route changes:
// on_data still gets the message, whole and decompressed.
//
// What the method RETURNS is the whole protocol between Ruby and this
// layer:
//   String  - sent to the client, in the SAME kind the message arrived
//             in (a binary message is answered binary, a text message
//             text) - so an echo is `data` and nothing else.
//   Symbol  - an RFC-relevant answer: a close code by name, or a
//             control frame. ws_symbol_action below is the whole list.
//   nil     - nothing is said. A callback that only DID something (a
//             write elsewhere, a counter) says nothing by falling off
//             its own end.
// Anything else closes the connection with 1011 and says why on
// stderr: a return value nobody can spell is a bug in the resource,
// not a message to guess at.
//
// PER-CONNECTION RUBY STATE IS THE POINT (#181, Nutzer-Entscheid:
// "you make Websockets stateless in the WebsocketResource class -
// reverse that"). A websocket connection IS a session, so its
// resource is one object per peer: `initialize` opens it, ivars carry
// whatever the session needs across messages, on_close ends it, and
// the object is released with the socket. (HTTP went the other way in
// the same breath: there a resource lives ONE REQUEST, because HTTP
// is stateless - resource.hpp's head says it.)
//
// What that costs, where it is paid: one mruby object per open
// websocket, plus whatever the app's initialize builds. h2.hpp's head
// measured what eager per-connection objects cost at scale (-12%
// throughput, +58% p99 at 7000 idle connections) - the difference is
// that this object is the FEATURE, and only a peer that actually
// upgraded gets one.
//
// Http1 knows only the two opaque pointers below - it never learns
// what a resource is, exactly as it never learned what a Resource is
// (http1.hpp declares resource_run and nothing else).




namespace webmachine {

// HOW BIG A MESSAGE MAY GET, which is the same question as "how big an
// mruby String may this layer build" - every delivered message is one
// String copied into the GC heap.
//
// The default is small on purpose. A whole message arriving in ONE
// frame is never buffered here: it goes straight from the receive pool
// into that one String, so it costs one copy. A FRAGMENTED message is
// assembled first, so its peak is two copies - and both are PER
// CONNECTION, of which there are as many as the derived capacity
// allows (tens of thousands since #169). A megabyte times that is not
// a number a peer should get to choose.
//
// A route that knows better says so, once, as a class method - the
// same shape the flow's konst callbacks have, read at fold, free per
// message:
//
//     def self.max_message = 8 * 1024 * 1024
//
// Past whatever stands, the close is 1009, which is the code RFC 6455
// 7.4.1 has for exactly this.
inline constexpr size_t kMaxWsMessageDefault = 64u * 1024;

// The route's resource, folded ONCE at route.websocket: the class
// frozen, on_data resolved, the route's own konst answers read.
// Nothing is looked up per message and nothing can be redefined
// behind an open socket. It holds no Ruby object - the CONNECTION
// does (#181).
struct WsResource;

// One peer: what is left of a connection that stopped being HTTP.
struct WsConn;

// Folds a resource class for a websocket route. False leaves the
// reason in err by name (not a Webmachine::WebsocketResource, no
// on_data).
bool ws_fold(mrb_state* mrb, mrb_value klass, WsResource& out, char* err, size_t errlen);

// Does this route accept RFC 7692 at all? Asked by the handshake
// BEFORE it parses a Sec-WebSocket-Extensions offer, so a route that
// says no never pays for the parse.
bool ws_wants_deflate(const WsResource* r);
WsResource* ws_resource_new();
void ws_resource_free(WsResource* r);

// Webmachine::WebsocketResource. Defined at gem init, BEFORE the
// request object (which hangs its accessor on this class as well as on
// Resource - the head is what both kinds of resource read).
void ws_init(mrb_state* mrb, struct RClass* wm);

// The handshake's own half, BEFORE the 101 goes out: runs on_open (if
// there is one) while `request` is still bound, and says whether this
// upgrade happens. True with `proto` empty = plain upgrade; non-empty
// = that is the Sec-WebSocket-Protocol answer. False leaves in
// `status` the HTTP status the resource named instead of an upgrade.
// The handshake's decision AND the peer's connection in one step
// (#181): this builds THIS peer's resource object and runs its
// `initialize`, whose return value is the answer - nil admits, a
// String admits and names the subprotocol, a Symbol refuses with an
// HTTP status. Admitted, the WsConn that owns the object comes back;
// refused, the object is dropped here and null comes back with the
// status. (Returning the connection is also what keeps the mrb_value
// out of http1.hpp, which is mruby-free by contract.)
WsConn* ws_admit(const WsResource* r, std::string& proto, uint16_t& status);

// The upgrade is answered: build the peer, with whatever
// permessage-deflate negotiation settled on (wsdeflate.hpp). Params
// with `on` false is a plain RFC 6455 connection and costs nothing.
void ws_open(WsConn* c, const wsdeflate::Params& deflate);

// Wire bytes for an upgraded connection. False = this connection ends
// once the sink has drained, exactly like Http1::feed's contract.
// `data` is UNMASKED IN PLACE (websocket.hpp says why): the buffer the
// Ring lends is this process's own pool.
bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink);

void ws_free(WsConn* c);

}  // namespace webmachine

// ------------------------------------------------------------------
// SERVER-SENT EVENTS (#102), the WHATWG spec's text/event-stream. Its
// own route table, like websockets and for the same reason: an SSE
// route is matched before the flow or not at all. Nothing of the
// decision graph applies - there is no conneg (the media type is
// fixed), no precondition (there is no representation to compare), no
// Content-Length (the body has no end until somebody ends it).
//
// WHAT MAKES IT DIFFERENT FROM EVERY OTHER TIER HERE: it is the first
// source in this tree that produces on ITS OWN SCHEDULE. Everything
// else answers bytes with bytes. An event stream is a request that is
// answered once, at the head, and then goes quiet for as long as the
// application likes. So the reactor's own second - the one it already
// wakes on for the timeout clocks (#180) - is the clock the stream
// runs on: once a second, per open stream, the resource is asked what
// it has. That costs one VM call per second per stream and not one
// timer anywhere.
//
// THE SURFACE, deliberately the WebsocketResource one (a stream is a
// session, so #181's rule holds): a Webmachine::SseResource stands on
// its own, is instantiated ONCE PER STREAM, and is fed by methods.
//
//     class Clock < Webmachine::SseResource
//       def initialize                  # optional - the OPEN hook
//         # This object is THIS stream's; ivars live as long as the
//         # connection. `request` is live - the head that asked, its
//         # headers and the route's bindings included, Last-Event-ID
//         # among them. nil accepts; a Symbol refuses with an HTTP
//         # status and the stream never opens.
//         @n = 0
//       end
//
//       def on_tick                     # required - once a second
//         @n += 1
//         return nil if @n % 5 != 0     # nothing to say this second
//         { event: 'tick', data: @n.to_s, id: @n.to_s }
//       end
//
//       def on_close                    # optional
//       end
//     end
//
// What on_tick RETURNS is the whole protocol:
//   nil / false - nothing this second. The stream stays open and
//                 costs nothing but the heartbeat below.
//   String      - one event's `data`. A String with newlines becomes
//                 several data: lines, which is what the spec says
//                 they mean.
//   Hash        - the fields by name: :data, :event, :id, :retry.
//                 :data may be a String or an Array of them.
//   Array       - several of the above, in one round.
//   :close      - the stream ends here, the connection closes.
// Anything else closes the stream and says why on stderr: a return
// value nobody can spell is a bug in the resource, not a message to
// guess at.
//
// THE HEARTBEAT is the server's, not the application's. A stream that
// says nothing for long enough is indistinguishable from a dead one
// to every proxy in between, so a bare comment (":\n\n", which the
// spec defines as ignorable) goes out when nothing else has. The
// route names the interval, as a DURATION through mruby-chrono like
// every other duration that crosses this boundary:
//
//     def self.heartbeat = 15.s     # default 15 seconds; 0 = never
//
// HTTP/1.1 ONLY, and refused by name elsewhere. The h1 answer is
// chunked (RFC 9112 7.1: each event is one chunk, and the stream ends
// with the terminal chunk), which is the only framing that lets the
// connection stay legal without knowing its own length. An HTTP/1.0
// client gets 505 - it has no chunked and no EventSource. HTTP/2 gets
// 501 for now: an unbounded DATA stream is stream-lifetime work that
// belongs with #172, and pretending otherwise would ship a half
// answer.


namespace webmachine {

// The route's resource, folded ONCE at route.sse: the class frozen,
// on_tick resolved, the heartbeat read. Holds no Ruby object - the
// STREAM does.
struct SseResource;

// One open stream: the resource instance, its heartbeat clock, and
// what the last second produced.
struct SseStream;

// Folds a resource class for an SSE route. False leaves the reason in
// err by name (not a Webmachine::SseResource, no on_tick).
bool sse_fold(mrb_state* mrb, mrb_value klass, SseResource& out, char* err, size_t errlen);
SseResource* sse_resource_new();
void sse_resource_free(SseResource* r);

// Webmachine::SseResource, defined at gem init beside the other two.
void sse_init(mrb_state* mrb, struct RClass* wm);

// The head is parsed and the route matched: build THIS stream's
// resource object and run its initialize, whose return value is the
// answer - nil opens the stream, a Symbol refuses with an HTTP
// status. Opened, the stream comes back; refused, null comes back and
// `status` says how. `request` must be bound by the caller.
SseStream* sse_open(const SseResource* r, uint16_t& status);

// One second has passed on this stream: ask the resource, and append
// whatever it said as chunked event bytes. False = the stream ends
// (the resource said :close, or said something nobody can spell).
// Appends nothing at all in the common quiet second.
bool sse_second(SseStream* s, int64_t now_s, std::string& sink);

void sse_free(SseStream* s);

}  // namespace webmachine

// ------------------------------------------------------------------
// WebSocket (#175), round one: the HANDSHAKE key and the FRAMING, and
// nothing else. No IO, no mruby, no connection state - bytes in, bytes
// out, the way embed.hpp cut h1 (#173). Everything here is protocol
// truth from RFC 6455, so it can be driven from a test binary and
// later by Autobahn without a socket in sight.
//
// Why this tree writes its own instead of taking a library: the
// framing IS this file - a bit test, a length, a four-byte mask - and
// every candidate library brought its own event loop, its own
// allocator, or its own buffer discipline, each of which is a thing
// this tree already owns and only owns once.
//
// What this file deliberately does NOT do: text-frame UTF-8
// validation (its caller does it through mruby-string-is-utf8, whose
// simdutf validates a whole buffer with SIMD - reimplementing that
// here would be the slow variant of a solved problem), and any policy
// about who may open a socket (that is the route's).
//
// Round two (#175, RFC 7692) added exactly one bit to this file: RSV1
// stopped being unconditionally illegal. The extension ITSELF - its
// negotiation and its zlib streams - is wsdeflate.hpp; what belongs
// here is only that a frame may now carry the bit, and only where 7692
// 6 puts it (the FIRST frame of a data message, never a continuation,
// never a control frame).


namespace webmachine {
namespace ws {

// RFC 6455 5.2: opcodes. The gaps are reserved and refused by name.
enum : uint8_t {
  kContinuation = 0x0,
  kText = 0x1,
  kBinary = 0x2,
  kClose = 0x8,
  kPing = 0x9,
  kPong = 0xa,
};

// RFC 6455 7.4.1: the close codes this tree can be the sender of.
enum : uint16_t {
  kCloseNormal = 1000,
  kCloseGoingAway = 1001,
  kCloseProtocolError = 1002,
  kCloseUnsupportedData = 1003,
  kCloseInvalidPayload = 1007,
  kClosePolicyViolation = 1008,
  kCloseTooBig = 1009,
  kCloseInternalError = 1011,
};

// RFC 6455 5.5: a control frame's payload is at most 125 bytes and it
// may not be fragmented. Both are refusals, not clamps.
inline constexpr size_t kMaxControlPayload = 125;

// The 24 bytes of "<key>258EAFA5-E914-47DA-95CA-C5AB0DC85B11" hashed
// and base64'd - RFC 6455 4.2.2 step 5.4. `out` takes 28 bytes plus no
// terminator. False: the key was not 24 base64 characters, which is
// the one thing the client half of the handshake must get right.
bool accept_key(const char* key, size_t key_len, char out[28]);

// What one parse produced. `payload` points INTO the caller's buffer,
// unmasked in place - a frame is never copied here.
struct Frame {
  uint8_t opcode = 0;
  bool fin = false;
  // RFC 7692 6: "the message is compressed". Only ever true when the
  // caller passed allow_rsv1 - i.e. when permessage-deflate was
  // negotiated for this connection.
  bool rsv1 = false;
  const char* payload = nullptr;
  size_t len = 0;
  size_t consumed = 0;  // bytes of the input this frame occupied
};

enum class Parse : uint8_t {
  kOk,       // a whole frame, in `out`
  kNeedMore, // a prefix - call again when more bytes arrived
  kError,    // protocol error; `code` says which close it earns
};

// ONE frame off the front of `data`. The buffer is WRITTEN to: a
// client frame is masked (5.3) and unmasking in place is what makes
// the payload usable without a copy, which is the whole reason this
// takes a mutable buffer.
//
// `max_payload` bounds what this side is willing to hold; past it the
// answer is kError with 1009 rather than an allocation the peer chose
// the size of.
//
// `allow_rsv1` is the permessage-deflate negotiation, and nothing
// else: false and RSV1 is the protocol error RFC 6455 5.2 makes it,
// true and it is legal on a first data frame and STILL an error on a
// continuation or a control frame (RFC 7692 6).
Parse parse(char* data, size_t len, size_t max_payload, bool allow_rsv1, Frame& out,
            uint16_t& code);

// A SERVER frame: never masked (5.1), FIN set unless the caller is
// fragmenting on purpose, RSV1 set when the payload is a
// permessage-deflate stream (RFC 7692 6). Returns the header length
// written into `head` (at most 10 bytes); the payload follows
// unchanged, which is why this writes a header instead of a buffer -
// the body goes out where it already lies.
size_t build_header(uint8_t opcode, bool fin, bool rsv1, size_t payload_len, char head[10]);

// A close frame's payload: the code big-endian, then the reason (7.1.6
// - at most 123 bytes of it, so the frame stays a legal control
// frame). Returns the payload length written into `out` (125 max).
size_t build_close_payload(uint16_t code, const char* reason, size_t reason_len,
                           char out[125]);

// The code a received close frame carries, and its reason. A zero
// length payload is 1005 "no status" (7.1.5) and NOT an error; a
// one-byte payload IS one (7.1.6 gives the code two bytes). False =
// malformed, answer 1002.
bool read_close(const char* payload, size_t len, uint16_t& code, const char** reason,
                size_t* reason_len);

}  // namespace ws
}  // namespace webmachine

// ------------------------------------------------------------------
// HTTP/1.1 framing as a Ring App: ONE framer (phr on the wire bytes,
// carry only when a head splits across receives), ONE writer (prebuilt
// response strings for every status the flow can speak, the running
// second PATCHES 29 date bytes in place - a response is a single
// append), ONE flow (the webmachine graph decides every status; the
// framer only ever decides wire validity). Every branch names its RFC
// clause. The Ring knows none of this; it hands bytes in and drains
// the sink.




namespace webmachine {

// The bound resource (resource.hpp owns the definition; Http1 stays
// mruby-free). resource_run answers decision + render inside ONE VM
// frame; resource_exception_begin lends a pending exception's message
// (copy before the next mruby call).
struct Resource;
struct ReqView;
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, const ReqView* req,
                      std::string* body, bool* have_body);
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);

// The websocket half (#175, wsconn.hpp owns both types and every line
// of mruby behind them). This writer only ever holds the two pointers
// and calls these four - it never learns what a websocket resource is,
// exactly as it never learned what a Resource is.
struct WsResource;
struct WsConn;
// Round two's permessage-deflate (#175, RFC 7692) is wsdeflate.hpp's
// entirely; this writer only carries the settlement from the
// handshake to the peer, so the NAME is enough here and the zlib
// header stays out of every translation unit that includes this one.
namespace wsdeflate { struct Params; }
// ws_admit builds the peer's connection when the resource admits it
// (#181: the object it carries is that peer's own, for as long as the
// socket lives) - null means refused, and status says how. No
// mrb_value crosses this header; it stays mruby-free.
WsConn* ws_admit(const WsResource* r, std::string& proto, uint16_t& status);
bool ws_wants_deflate(const WsResource* r);
void ws_open(WsConn* c, const wsdeflate::Params& deflate);
bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink);
void ws_free(WsConn* c);

// The event stream (#102), the same mruby-free shape: sse_open builds
// the stream when the resource opens it (null = refused, status says
// how), sse_second asks it what this second holds, sse_free ends it.
struct SseResource;
struct SseStream;
SseStream* sse_open(const SseResource* r, uint16_t& status);
bool sse_second(SseStream* s, int64_t now_s, std::string& sink);
void sse_free(SseStream* s);

// h2.hpp owns the definition (it pulls lshpack.h; this header stays
// lean). A connection that never speaks the preface carries only the
// null pointer. h2_free lives in http2.cpp where the type is complete.
struct H2State;
void h2_free(H2State* h2);

// assets.hpp owns both (#170). Null = no asset tier; requests never
// pay a lookup they did not configure.
class Assets;
struct AssetEntry;

// RFC 9110 §5.4 allows refusing oversized fields; 8k is the fleet
// convention (nginx, h2o) and bounds one head's work - 431 past it.
inline constexpr size_t kMaxHead = 8192;
// Bodies are skipped at this layer, but skipping is still work; 1 MiB
// bounds it - 413 past it (RFC 9110 §15.5.14).
inline constexpr size_t kMaxBody = 1u << 20;
inline constexpr size_t kMaxHeaders = 64;
// #147 Tor 1, revised (Nutzer-Entscheid 2026-08-22): a fixed floor
// replaces the per-connection TCP_MAXSEG query this tree used to make
// at accept. The kernel would not give the answer through the ring at
// all - io_uring_cmd_getsockopt (io_uring/cmd_net.c) hard-refuses
// every level but SOL_SOCKET, confirmed live - and the only bridge
// (IORING_OP_FIXED_FD_INSTALL + getsockopt(2) + close(2), see
// ring.hpp's on_accept history) cost a whole extra ring round-trip of
// latency on every TCP accept, paid before the connection's first
// recv. 1280 is the IPv6 minimum MTU (RFC 8200 §5): the floor every
// path MUST carry, the one a real fleet clamps to in practice (LTE
// behind a VPN). One segment's payload at the narrowest legal MTU
// runs ~1208-1240 bytes (1280 minus IP/TCP headers minus 12 bytes of
// timestamp option), so head+body >= 1280 is safely >= 2 segments on
// EVERY path - compression there can only ever save a packet. On a
// wider path the band between 1280 and the real MSS spends a little
// CPU compressing a response that still fits one segment; that is the
// CHEAP direction to be wrong in, chosen deliberately.
//
// This is NOT a return to kAssumedMss=1460 (commit 7755820, "Measure
// the MSS, never assume one") - that guess erred the EXPENSIVE way,
// overestimating the segment and refusing compression that would have
// saved packets. A floor errs harmlessly (a little wasted CPU, never
// a missed saving); an assumed ceiling erred the other way. The two
// are opposites, not a repeat.
inline constexpr size_t kCompressFloor = 1280;
// One delivery round's budget (#168, Gebot 18: bounded work per tick):
// a source hands over at most this much per continuation, so a slow
// consumer holds one round's worth of pointers, never a whole file.
inline constexpr size_t kDeliverChunk = 64u * 1024;

// THE WARM BUDGET: at or below this a body is COPIED into the response
// buffer and leaves with its head in one append; above it the body
// becomes a source, handed over as POINTERS a round at a time.
//
// It is one delivery round, which is a structural line rather than a
// tuned one: a body that fits in a single round has nothing to gain
// from being a source - the head would have to leave on its own first
// and there is no second round for that to amortise over.
//
// THE MEASUREMENT THIS REPLACED IS WORTH KEEPING, because it is why
// the number here is not the one the older tree used. That tree put
// the crossover at 4 KiB and this one carried it over, which produced
// a 32 KiB collapse on forgecore (0.22x). The cause was not the
// budget: bodies above it went through splice, and splice was being
// compared against a path that copied TWICE (mapping -> buffer ->
// socket). Against the pointer path it actually loses at every size:
//
//   forgecore, -t4 -c400, splice against the same server without it
//       4 KiB  0.99x    32 KiB  1.01x   256 KiB  0.63x    1 MiB  0.79x
//
// So splice is gone, and what remains is one kernel copy out of the
// mapping - which is also what makes this budget a small number
// rather than a tuning surface.
//
// Settable anyway, because the crossover belongs to the machine and
// the asset mix rather than to this file (#166 folds WM_WARM_BUDGET
// into the config; the env knob is what exists today).
inline constexpr size_t kWarmBudgetDefault = kDeliverChunk;

// The router's miss, carried where a route index is carried (#116). A
// miss answers the prebuilt 404 before B13 - before any method test,
// so POST on an unknown path is 404 and never 405.
inline constexpr uint16_t kNoRoute = 0xffff;

class Http1 {
 public:
  struct Conn {
    // Head bytes a receive ended in the middle of. Capacity survives
    // clear(): a warm connection allocates nothing. An h2 connection
    // reuses it as its frame buffer.
    std::string carry;
    size_t body_skip = 0;  // Content-Length bytes still owed by the wire
    uint8_t listener = 0;  // which listener accepted - whose app this is
    // Undecided until the first bytes: the client preface upgrades to
    // h2 (RFC 9113 3.4), anything else is h1 forever.
    bool fresh = true;
    H2State* h2 = nullptr;  // allocated on the preface, never before
    // The h1 delivery model's source (#168): null on the fast path -
    // that null IS the model's cost there. Set only while a body
    // larger than one kDeliverChunk is being delivered; more() pulls
    // the next chunk each time the sink drains. h1 is serial, so one
    // source suffices; bytes pipelined behind it wait in the carry.
    const AssetEntry* xfer = nullptr;
    // The transfer's window into the wire body: [xfer_off, xfer_end).
    // A full body is {0, wire_len}; a 206 (#148) is the satisfied
    // range - the SAME machinery walks both.
    size_t xfer_off = 0;
    size_t xfer_end = 0;
    // Is this connection's transport packetized (TCP), or a unix
    // stream behind a proxy (#147)? Set once at accept, from the
    // Ring's own listener table - see ring.hpp's on_accept. Replaces
    // the per-connection TCP_MAXSEG query this tree used to make
    // (Nutzer-Entscheid 2026-08-22, #147 Tor 1 revision): a unix
    // listener's answer is always false, the same as before.
    bool packetized = false;
    // Past the 101 this connection is not HTTP any more (#175): every
    // byte goes to the websocket half and nothing here reads a head
    // again. Null is the whole cost for every connection that never
    // upgrades.
    WsConn* ws = nullptr;
    // An open event stream (#102). Like `ws`, this connection stopped
    // being a request/response pair the moment the head was answered:
    // nothing here reads another head, and the bytes that leave come
    // from the SECOND, not from anything the peer sends. Null is the
    // whole cost for every connection that never asked for one.
    SseStream* sse = nullptr;
    // The peer's RAW sockaddr bytes, for the access log. The RING
    // fills both (it owns the socket and the storage); the record
    // ships them raw and webmachine-logd spells the address at the
    // operator's privacy level. 0 = unknown or unix, spelled "-".
    const void* peer = nullptr;
    uint8_t peer_len = 0;
    void reset(uint8_t li, bool pkt) {
      peer_len = 0;
      carry.clear();
      body_skip = 0;
      listener = li;
      packetized = pkt;
      fresh = true;
      h2_free(h2);
      h2 = nullptr;
      ws_free(ws);
      ws = nullptr;
      sse_free(sse);
      sse = nullptr;
      xfer = nullptr;
      xfer_off = 0;
      xfer_end = 0;
    }
    ~Conn() {
      h2_free(h2);
      ws_free(ws);
      sse_free(sse);
    }
  };

  // ONE APPLICATION as this writer sees it (#116 slice 2): its route
  // table (borrowed - the AppSpec owns it) and its resources, one per
  // route, in the SAME order route.add registered them. The listener
  // this app was bound to is its INDEX in the array handed to the
  // constructor, which is also the index the Ring writes into every
  // connection at accept - that is the whole of "whose connection is
  // this".
  struct AppInput {
    const RouteTable* table = nullptr;
    const Resource* const* resources = nullptr;
    size_t nroutes = 0;
    // The app's websocket routes, its own table (#175) - empty where
    // the app has none, which is one null pointer at the upgrade and
    // nothing anywhere else.
    const RouteTable* ws_table = nullptr;
    const WsResource* const* ws_resources = nullptr;
    size_t ws_nroutes = 0;
    // The app's event-stream routes (#102), same shape again.
    const RouteTable* sse_table = nullptr;
    const SseResource* const* sse_resources = nullptr;
    size_t sse_nroutes = 0;
  };

  // Builds every response every route of every app can speak, once, and
  // stamps the date. From here on only the 29 date bytes ever change.
  Http1(const AppInput* apps, size_t napps, Assets* assets = nullptr);
  // One app, one listener - the shape everything but a multi-app file
  // has, spelled so a caller with a single table needs no array.
  Http1(const RouteTable& table, const Resource* const* resources, size_t nroutes,
        Assets* assets = nullptr);

  // The Ring's per-wake hook: patch the date bytes when the wall-clock
  // second changed. Never runs per request.
  void on_tick();

  // True while this connection still owes bytes the Ring has not been
  // handed yet (#168). The Ring asks BEFORE sending, so a send that
  // has more behind it can carry MSG_MORE instead of putting a small
  // segment on the wire and waiting out the peer's delayed ACK - the
  // stall the previous tree measured at 44.30ms average, 1,118 ->
  // 31,077 req/s once fixed. Const and cheap: two pointer tests.
  bool pending(const Conn& st) const;

  // Does this connection carry an event stream (#102)? The Ring asks
  // once per second per connection, so it is one pointer test.
  bool timed(const Conn& st) const { return st.sse != nullptr; }

  // Feed wire bytes; responses land in sink (the connection's out/next,
  // whichever accumulates). False: the connection ends once everything
  // queued has drained - wire-invalidity paths and Connection: close.
  // What a source hands the Ring for one round (#168: "eine Quelle
  // liefert einen Plan, kein Byte"): POINTERS to bytes that already
  // exist - the deflate stream where it lies in the mapping, the 18
  // framing bytes in the entry table. They leave with whatever is in
  // the sink as ONE sendmsg, so nothing is copied in this process.
  // niov == 0 means the round put its bytes in the sink instead.
  struct Plan {
    // A segment is either bytes that already exist somewhere stable -
    // the mapping, the entry table - or a RANGE OF THE SINK. h2 needs
    // both, ALTERNATING: a 9-byte DATA frame header out of the sink,
    // that frame's payload straight out of the mapping, again and
    // again. The sink is a std::string the round is still appending
    // to, so its address is not knowable while the plan is built; the
    // offset is. The Ring resolves it when it arms the send, by which
    // time the sink is final and nothing more will be appended.
    //
    // Seg is bare POD and callers write `Plan p;`, not `Plan p{}`:
    // only [0, nseg) is ever read, and value-initializing the array
    // would memset 3 KB on EVERY continuation - more() runs after
    // every drained send, on hello as much as on a transfer.
    struct Seg {
      const char* base;  // null = a range of the sink
      size_t off;        // sink offset, when base is null
      size_t len;
    };
    // THE ROUND'S ONLY BOUND - there is no byte budget on top. A round
    // carries as much as there is work and window, and how much of it
    // the socket takes is not guessed at: the kernel keeps what fits
    // in the sndbuf and the short write says so, exactly the way
    // -ENOBUFS speaks for the recv buffer ring. (Asking first was
    // measured and buried: sndbuf - SIOCOUTQ overclaims by up to 2.4%
    // on a big buffer and UNDERCLAIMS - negative remainder - on small
    // ones, because tcp_sendmsg admits by sk_wmem_queued, overshoots
    // sk_sndbuf by design, and SIOCOUTQ counts payload only. A number
    // without a stable sign cannot be margined.) The remainder resumes
    // from Conn::sent without the App being asked again.
    //
    // So capacity is what keeps one connection from taxing the rest
    // (#138), and it is a bound with a reason, not an invented byte
    // count: a DATA frame costs its header (one sink run) plus at most
    // three payload segments (a deflated entry's wire body is gzip
    // header + mapping + trailer; stored is one), and consecutive sink
    // bytes coalesce into the open run, so anything that is only sink
    // costs ONE segment for the whole round.
    //
    // THE NUMBER IS IOV_MAX'S, not ours: 1023 plus the Ring's prepend
    // slot is exactly the 1024 iovecs one sendmsg may carry (Linux
    // UIO_MAXIOV) - the kernel's ceiling is the capacity, nothing
    // invented sits below it. It has to be this large because a -m32
    // batch of MEDIUM bodies must fit one round: at 128 segments a
    // 256 KiB response cost ~33 segments, so a 32-stream batch was cut
    // into 8 rounds where the old inline copy had needed one, and
    // forgecore measured that cut as -26% (2026-08-23, the second
    // round-count regression of this file's history - the first was a
    // byte budget). A 4 KiB gzip response is 4 segments, so 32 of
    // them sat exactly AT the old 128 and split into two rounds: -15%.
    // h1 has no framing inside a body, so its transfer is at most
    // three segments however large the body - capacity never cuts it.
    static constexpr unsigned kSegs = 1023;
    Seg seg[kSegs];
    unsigned nseg = 0;
    size_t iov_len = 0;  // total across seg
    // The round's BYTE bound, set by the Ring from the socket's own
    // accounting (SO_MEMINFO: sndbuf minus what is queued, the same
    // arithmetic sk_stream_wspace uses). 0 = unbounded. A round built
    // within it is accepted inline by the kernel; one built past it
    // short-writes and then WAITS - a full TCP socket signals
    // writability only at one-third free, so the remainder sleeps out
    // a third of the buffer's drain (measured: 1 MiB responses at
    // 8 MiB rounds ran at 0.6x their 1 MiB-round speed on forgecore,
    // 0.3x in the container). Soft: overshooting by one frame is a
    // race the short write corrects, not a fault.
    size_t byte_cap = 0;
  };

  // plan: nullable. Non-null only when the Ring can arm a plan in this
  // very round (no send in flight) - then an asset body leaves WITH
  // its head in one sendmsg, as pointers. Null keeps the classic
  // shape: bodies above the warm budget park and more() delivers.
  bool feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan);


  // The delivery model's continuation (#168): the Ring calls this when
  // the connection's sink has fully drained - the one signal BOTH
  // protocols produce (h1 has no window; its only backpressure is the
  // send CQE). h1 hands over the next slice of an active transfer as
  // POINTERS; h2 re-runs the parked-stream flush, which hands over the
  // same way - its DATA frame headers are sink runs, its payloads are
  // pointers, alternating (WINDOW_UPDATE remains its second trigger,
  // and THAT one still copies: it is mid-parse, with other frames
  // already in the round's sink). Same contract as feed: false ends
  // the connection once everything queued has drained.
  bool more(Conn& st, std::string& sink, Plan& plan);

  // The access log (accesslog.hpp): this writer FORMATS lines, the
  // Ring flushes the buffer. Opt-in - enable_access_log() is the only
  // way a line is ever built.
  AccessLog* access_log() { return &alog_; }
  void enable_access_log() { alog_.enabled = true; }

 private:
  // Defined below, next to the other per-app state; named here because
  // ws_upgrade takes one.
  struct AppSlot;

  // A prebuilt response whose date field sits at a fixed offset.
  struct Resp {
    std::string bytes;
    size_t date_off = 0;
  };
  // Connection semantics per RFC 9112 §9.3: a persistent 1.1 response
  // carries NO Connection header, a persistent 1.0 response echoes
  // keep-alive, anything closing spells close.
  struct Variants {
    Resp plain, keep, close;
  };
  // h2's precomputed response header block - ONLY what never changes
  // (:status, konst content-type, allow), encoded never-indexed so the
  // bytes are connection-independent. Built once by h2_build_block
  // (http2.cpp owns the encoding); per response it costs a 9-byte
  // frame header (stream id + flags) + one memcpy.
  struct H2Block {
    std::string bytes;
  };

  // ONE ROUTE'S VOICE (#116). The status supply below (store_/index_)
  // stays ONE per app - a 400 is the same bytes whoever was going to
  // answer, and the date patch walks it once. Everything that carries
  // a RESOURCE's own voice - its 200 in every shape, its Allow, its
  // negotiated type, its #147 gzip decision, its h2 blocks - lives
  // here, one per route, and the router's verdict is the only thing
  // that chooses between them. A konst request therefore pays one
  // table walk and then indexes: no allocation, and no branch the
  // single-resource tree did not already have.
  struct Bundle {
    flow::KonstSet konst;
    const Resource* res = nullptr;
    // status -> slot in the SHARED store_. It starts as a copy of the
    // generic table and then points 200 and 405 at this route's own
    // entries, which were appended to that same store_ at setup. That
    // is why a matched request still indexes ONCE, with no status
    // compare and no second table to consult - the multi-resource cut
    // costs setup memory (two arrays of slots per route) and not a
    // single per-request branch. uint16_t, not uint8_t: two slots per
    // route would otherwise cap the app at ~113 routes.
    std::array<uint16_t, 600> index {};
    bool dynamic_body = false;
    bool bound = false;    // any runtime tier at all
    bool gzip_ok = false;  // #147's setup-time decision, see below
    Variants ok_head;      // 200 for HEAD (RFC 9110 9.3.2): head, no body
    // Heads up to (not including) Content-Length: the assembly points
    // for per-request bodies (200) and for exceptions answering as the
    // negotiated type (500).
    Variants ok_prefix;
    // #147: identity always carries the resource's own ok_prefix;
    // these two exist only where gzip_ok is true - a 200 head ending,
    // respectively, in "Vary: Accept-Encoding\r\n" alone (identity was
    // chosen, but the resource DOES vary by coding - RFC 9110 12.5.5)
    // or in "Content-Encoding: gzip\r\nVary: ...\r\n" (gzip was
    // chosen). Prebuilt like every other head; only the body bytes and
    // which of the three prefixes gets used are decided per request.
    Variants ok_prefix_vary;
    Variants ok_prefix_gzip;
    Variants err_prefix;
    H2Block h2_err;  // 500 in the negotiated type (bound routes only)
    // The fast lane's DATA half: a whole precomputed DATA frame
    // (header + konst.body), stream id still zero at its fixed offset
    // (5) - h2_answer patches those 4 bytes and appends the rest
    // untouched. Only valid when !bound (konst.body never varies);
    // bound resources and the 500 exception body vary per request and
    // keep the dynamic DATA path.
    std::string h2_data200;
  };

  // The one setup body both constructors run.
  void build(const AppInput* apps, size_t napps);
  static void build_variants(Variants& v, uint16_t status, const char* extra,
                             const char* body, const char* date);
  void build_status(uint16_t status, const char* extra, const char* body);
  void build_bundle(Bundle& b, const Resource* res);
  static void patch_date(Variants& v, const char* core);
  // prefix + hand-spelled Content-Length + (unless HEAD) the lent body.
  static void assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                       bool head_only);
  // #147: the one place a dynamic 200 body picks identity or gzip.
  // Called only when the route's gzip_ok - every other route never
  // reaches here, and pays nothing beyond that one bool test.
  void assemble_dynamic(const Conn& st, const flow::ReqFacts& facts, const http::ReqValues& vals,
                        const Resp& prefix_id, const Resp& prefix_gz, bool head_only,
                        std::string& sink);
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];  // every status here came from the tables
  }
  bool fail(Conn& st, uint16_t status, std::string& sink, uint8_t log_flags = 0);
  // The upgrade (#175): answers 101 (or the refusal the route earned)
  // and switches the connection over. `rest`/`rest_len` are the bytes
  // that came behind the handshake in the same receive - a client that
  // sends its first frame immediately is not made to wait for another
  // packet. False = this connection ends once the sink has drained.
  // `hdrs` is the phr_header array off feed's own frame, passed as
  // void* so this header stays free of picohttpparser (request.cpp is
  // where that shape is known - request.hpp says the same).
  bool ws_upgrade(Conn& st, const AppSlot& slot, int route, const char* path, size_t path_len,
                  const RouteSpans& spans, const char* key, size_t key_len, const void* hdrs,
                  size_t nhdr, const char* rest, size_t rest_len, std::string& sink);

  // The event stream's own head (#102): answers 200 with the chunked
  // framing and switches the connection over to the second, or
  // answers the refusal the route earned. False = this connection
  // ends once the sink has drained.
  bool sse_begin(Conn& st, const AppSlot& slot, int route, const char* method,
                 size_t method_len, const char* path, size_t path_len,
                 const RouteSpans& spans, const void* hdrs, size_t nhdr, int minor,
                 flow::Method m, const http::ReqValues& vals, uint8_t lflags,
                 std::string& sink);

  void h2_build_block(H2Block& b, uint16_t status, const std::string* ctype,
                      const std::string* allow);
  // Lane 2: whatever CHANGES goes through ls-hpack's encoder and the
  // connection's dynamic table. Today that is the date (changes per
  // second - one insert per second per connection, a one-byte
  // reference in between); the value tiers (etag, location, ...) join
  // it when they land.
  static bool h2_enc_field(void* enc, unsigned char*& ep, unsigned char* eend,
                           const char* name, size_t nlen, const char* val, size_t vlen);

  // The h2 half (http2.cpp): the same konst/resource machinery
  // answers; only the serialization differs - HPACK + HEADERS/DATA
  // frames into the same sink. Return value = feed's contract.
  bool h2_begin(Conn& st, std::string& sink);
  bool h2_feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan);
  bool h2_error(Conn& st, uint32_t code, std::string& sink);
  void h2_rst(Conn& st, uint32_t stream_id, uint32_t code, std::string& sink);
  bool h2_dispatch(Conn& st, uint32_t stream_id, bool end_stream, std::string& sink);
  // `route` is the router's verdict for this stream, parked with the
  // facts when a body is still owed; kNoRoute answers the prebuilt 404
  // the miss earned, before B13 and before any method test.
  // `req` is what a runtime callback may ask about this request (#116
  // slice 4), built by the caller because only the caller knows where
  // the bytes are: the live decode buffer for a request answered
  // inside its own dispatch, the stream's own copy for one that
  // parked. Null where no resource can ask (a router miss).
  // A parked request's view, rebuilt from the stream's own copy of the
  // target (http2.cpp says why the spans cannot be parked with it).
  // Null = no route, so nothing can ask.
  const ReqView* h2_parked_view(Conn& st, const std::string& target, ReqView& out);
  void h2_log(Conn& st, const flow::ReqFacts& facts, const char* target, size_t tlen);
  bool h2_answer(Conn& st, uint32_t stream_id, const flow::ReqFacts& facts, bool head_only,
                 uint16_t route, const ReqView* req, std::string& sink);
  // plan == nullptr: every byte lands in the sink, which is what the
  // WINDOW_UPDATE call site wants (it is mid-parse, the round's sink
  // already holds other frames). With a plan, asset payload leaves as
  // POINTERS and only the framing is copied.
  void h2_flush_pending(Conn& st, std::string& sink, Plan* plan);
  // The asset tier's h2 half (#170): per-entry never-indexed blocks
  // built at setup (the HPACK spelling lives in http2.cpp), answered
  // with the same window/park discipline h2_answer has - only the body
  // is segments over the mapping instead of one buffer.
  void h2_build_asset_blocks(AssetEntry& e);
  void h2_build_asset_shared();
  // win_off/win_end: the answer's window into the wire body - full for
  // 200, the satisfied range for 206 (#148); ignored otherwise.
  bool h2_asset_answer(Conn& st, uint32_t stream_id, const AssetEntry& e, uint16_t status,
                       bool head_only, size_t win_off, size_t win_end, std::string& sink);

  // One app's place in this writer (#116 slice 2): which table its
  // requests walk, and where its bundles start in the ONE bundles_
  // vector. Indexed by the connection's listener - the Ring wrote that
  // number at accept, so the lookup is an array index and never a
  // search. Bundles stay in one vector deliberately: the date patch is
  // then ONE loop per second no matter how many apps a process serves.
  struct AppSlot {
    const RouteTable* table = nullptr;
    uint16_t base = 0;   // first bundle index
    uint16_t count = 0;  // how many (the router's verdict is < count)
    // The websocket table and where this app's websocket resources
    // start in ws_res_ - the same base-plus-verdict shape, for the
    // same reason (#116 slice 2).
    const RouteTable* ws_table = nullptr;
    uint16_t ws_base = 0;
    const RouteTable* sse_table = nullptr;
    uint16_t sse_base = 0;
  };

  time_t sec_ = 0;
  // Borrowed route tables, one per listener. ONE walk per request
  // decides which bundle answers; both protocols walk the SAME table of
  // the SAME app in the same order (h1 in feed, h2 in h2_dispatch).
  std::vector<AppSlot> apps_;
  std::vector<Bundle> bundles_;  // every app's routes, back to back
  // Every app's websocket resources, back to back. Borrowed: the
  // AppSpec owns them, like every table here.
  std::vector<const WsResource*> ws_res_;
  // Every app's event-stream resources, back to back, borrowed the
  // same way.
  std::vector<const SseResource*> sse_res_;
  // The generic status supply, one per app. It also holds a 200 and a
  // 405 slot, built neutrally so index_ stays total for any status the
  // flow tables can name - a MATCHED route never reads those two (its
  // bundle owns them), and a miss only ever reads 404.
  std::vector<Variants> store_;
  std::array<uint16_t, 600> index_ {};  // status -> store_ slot
  // h2 blocks, parallel to store_ via index_.
  std::vector<H2Block> h2_store_;
  // Asset-tier refusals for h2: 405 with Allow: GET, HEAD and 406 with
  // Vary - the entry blocks live on the entries themselves.
  H2Block h2_asset405_;
  H2Block h2_asset406_;
  Assets* assets_ = nullptr;
  // Read once at construction from WM_WARM_BUDGET (see kWarmBudgetDefault).
  size_t warm_budget_ = kWarmBudgetDefault;
  AccessLog alog_;
  // The h2 answer functions record what they answered; h2_dispatch -
  // where the :path bytes are still alive - writes the line.
  uint16_t alog_status_ = 0;
  size_t alog_bytes_ = 0;
  std::string body_;  // the run frame's rendered bytes; capacity survives
  // #147: the gzip encoding of body_ for the current request, when the
  // route's gzip_ok chose to compress. Capacity survives across
  // requests like body_ does - a warm connection reusing a resource
  // that compresses every response allocates nothing after the first.
  std::string gz_body_;
  // The current IMF-fixdate value; h1 patches it into prebuilt bytes,
  // h2 encodes it per response (the peer's dynamic table indexes it
  // after the first send).
  char date_[29] = {};
};

}  // namespace webmachine

// ------------------------------------------------------------------
// The application (#116): `Webmachine::Application.new { |app| ... }`
// is the app's whole surface, and it is C - the block configures a
// listener, adds routes and leaves a `ready` hook, and by the time it
// returns everything a request will ever need is a table.
//
// The app file defines ONE method, `main`. app_load calls it; the
// constant scan that used to go looking for a resource class is gone
// (there is no hook, no ivar, no mrb->ud, and now no scan either).




namespace webmachine {

// One application: its listener, its routes, its ready hook. Built
// entirely at setup - nothing in here is read on a request path except
// the RouteTable and the Resources it points at.
struct AppSpec {
  // EXACTLY ONE of the three forms (conf.port / conf.unix_path /
  // conf.url); a second one refuses by name.
  enum class Form : uint8_t { kNone, kPort, kUnix, kUrl };
  Form form = Form::kNone;
  int port = 0;
  std::string unix_path;
  std::string url_host;  // conf.url's authority; the ring binds INADDR_ANY
  // conf.url reads both ways: before the bind it spells where this app
  // WANTS to be, after it where it really is.
  std::string bound_url;
  bool bound = false;
  RouteTable table;
  // Parallel to table's routes, by index. unique_ptr because the run
  // frame's cfunc env borrows a Resource's ADDRESS (resource.hpp).
  std::vector<std::unique_ptr<Resource>> resources;
  // WEBSOCKET ROUTES ARE THEIR OWN TABLE (#175). They share nothing
  // with the flow: no status, no negotiation, no method test - a
  // websocket route is matched before all of that or not at all, so
  // giving it a second table costs one pointer compare on the upgrade
  // path and keeps the flow's table exactly as wide as the flow.
  RouteTable ws_table;
  std::vector<std::unique_ptr<WsResource, void (*)(WsResource*)>> ws_resources;
  // EVENT-STREAM ROUTES ARE THEIR OWN TABLE TOO (#102), for exactly
  // the reason the websocket ones are: an SSE path is matched before
  // the flow or not at all, so a third table costs one pointer
  // compare on a path the flow would have had to widen for.
  RouteTable sse_table;
  std::vector<std::unique_ptr<SseResource, void (*)(SseResource*)>> sse_resources;
  mrb_value ready = mrb_nil_value();
  bool have_ready = false;
  bool registered = false;
};

// The gem's Application surface, defined next to Webmachine::Resource.
void application_init(mrb_state* mrb, struct RClass* wm);

// Loads the app's bytecode and calls its `main`. Every refusal (a .rb
// path, a load-time raise, a missing `main`, anything the block
// refused) lands in err by name.
bool app_load(mrb_state* mrb, const char* path, char* err, size_t errlen);

// Every application `main` registered, in registration order - that
// order IS the listener order, and a connection's listener index is
// how the writer finds its app again (#116 slice 2). False with a
// named reason: none registered, more than the ring has listeners, or
// one without a listener of its own.
bool app_registered_all(std::vector<AppSpec*>& out, size_t max_listeners, char* err,
                        size_t errlen);

// The app a server without --app serves: one splat route on
// webmachine-ruby's unbound resource, which is exactly what this
// server answered everywhere before routes existed.
AppSpec* app_default();

// What the listener REALLY became, once the ring has bound it: this is
// what conf.url reads back.
void app_mark_bound(AppSpec& spec, const char* unix_path, int port);

// The ready hook, called after the bind and before the first accept.
// False leaves the raise's reason in err.
bool app_ready_run(mrb_state* mrb, AppSpec& spec, char* err, size_t errlen);

}  // namespace webmachine

// ------------------------------------------------------------------
// The serve loop as a Ruby surface (#116 slice 3): `Webmachine.run`,
// `Webmachine.tick(budget)` and `Webmachine.fd`.
//
// Slice 1 and 2 put everything a request needs into tables at setup;
// what was left was the loop itself, which lived in the server tool
// and could not be entered from Ruby at all. It lives here now, as ONE
// process-wide server built on first use out of the applications
// `main` registered - the tool and an embedder enter the SAME object
// through the same three doors, so there is no second loop to keep in
// step with this one.
//
// The three doors, and why exactly these:
//   run                 - the tool's own loop: block, serve, return
//                         when the stop signal's completion lands.
//   tick(budget = nil)  - ONE bounded step for an embedder that owns
//                         its own loop. Gebot 18 as an API: the budget
//                         bounds the WORK, not just the wait.
//   fd                  - what such an embedder polls between ticks,
//                         so an idle server costs its host nothing.



namespace webmachine {

// What the INVOCATION decides, as opposed to what the app file does.
// The tool states this once, before `main` runs; nothing here is
// reachable from Ruby, deliberately - an app file that could rewrite
// the CLI would make the command line a suggestion.
struct ServerOptions {
  const char* assets_path = nullptr;  // --assets, null = no asset tier
  // --mime-types, null = find the machine's own database (MimeDb).
  // Only ever read when an asset tier exists - it is the only thing
  // in the tree that asks a filename what it is.
  const char* mime_path = nullptr;
  const char* log_path = nullptr;     // --log, null = no access log (opt-in)
  // --log-privacy none|anon|full - the amount of PRIVACY the peer
  // gets (none = full addresses + GDPR warning; default anon; logd
  // validates the word).
  const char* log_privacy = nullptr;
  int stop_fd = -1;                   // the signalfd the ring polls
  const char* cli_unix = nullptr;     // --unix override
  int cli_port = 0;                   // --port override
  const char* app_path = nullptr;     // only ever named in messages
  bool have_uring = false;            // URING_AVAILABLE, asked once in the tool
  // #166 [tune] knobs; 0 = the ring's own default. The tool merges
  // the config file in before speaking, so these already carry it.
  unsigned sq_entries = 0;
  int backlog = 0;
  int to_header = 0;  // #180 timeout clocks, seconds
  int to_send = 0;
  int to_idle = 0;
};
void server_options(const ServerOptions& opts);

// WHICH io backend got linked was settled at build time (#171), and
// there is no second one in the binary to fall back to. This says so -
// loudly, once, at startup - when the select implementation is what
// answers, and refuses BY NAME when the real ring is in and this
// machine cannot run it. Both entries (this server and the echo floor)
// ask it, so the words exist once.
bool server_backend_ok(bool have_uring, char* err, size_t errlen);

// Webmachine.run / .tick / .fd, defined next to Application.
void server_init(mrb_state* mrb, struct RClass* wm);

// The tool's entry: build the server if Ruby has not already, then
// loop until the stop signal. 0 = a clean stop; anything else left a
// named reason in err.
int server_run(mrb_state* mrb, char* err, size_t errlen);

// Did Ruby already enter run or tick itself? Then `main` served, and
// the tool has nothing left to do.
bool server_entered();

}  // namespace webmachine

// ------------------------------------------------------------------
// The config file (#166): the INVOCATION, as a file. webmachine.toml
// says what the command line says - listener override, app bytecode,
// asset archive, access log, pidfile, ring tunables - in the format
// every deployment tool already reads and writes.
//
// PRECEDENCE, one line: CLI > file > the app's conf. The file is the
// invocation's second voice, so the first (the typed flags) beats it,
// and both beat what `main` configures - exactly the --port/--unix
// rule that already existed, extended one seat down.
//
// WHAT THE FILE CANNOT DO (user decision, final): create resources.
// No routes, no bodies, no apps - Ruby owns behavior, the file owns
// operation. A server with no app file still serves: the default
// splat resource and the asset archive are apps the TREE provides,
// not ones the file created.
//
// The parser is mruby-toml, through the VM the process already
// carries (user decision): config is read ONCE at startup, never on
// a request path, so the Ruby-side surface is exactly enough and the
// binary carries no second TOML implementation.
//
// Every refusal is by name: a TOML error carries the parser's own
// words, an unknown key inside a section is a typo that must not
// silently do nothing, a wrong type or value says what it is and
// what it takes.



namespace webmachine {

// Parsed and validated webmachine.toml. Strings are owned copies -
// the caller keeps this alive for the run; empty string / 0 = the key
// was absent (every valid value is non-empty / non-zero).
struct Config {
  std::string path;  // where it came from, for messages

  // [server]
  std::string unix_path;  // unix = "PATH" - listener override, like --unix
  int port = 0;           // port = N     - listener override, like --port
  std::string app;        // app = "FILE.mrb"
  std::string assets;     // assets = "FILE.zip"
  // mime_types = "PATH" - the media-type database to read instead of
  // hunting for the machine's own (MimeDb names the order it hunts in).
  std::string mime_types;
  std::string pidfile;    // pidfile = "PATH"

  // [log]
  std::string log_file;     // file = "PATH" (the log is opt-in, as ever)
  std::string log_privacy;  // privacy = "none" | "anon" | "full"

  // [tune] - setup-only ring knobs; 0 = the tree's default
  int backlog = 0;           // listen backlog (default 511, ring.hpp)
  unsigned sq_entries = 0;   // SQ size first ask (default 32768, halves on refusal)
  int header_timeout = 0;    // #180: whole head, seconds (default 60)
  int send_timeout = 0;      // #180: between wire progresses (default 60)
  int idle_timeout = 0;      // #180: keep-alive quiet time (default 75)
};

// Parses and validates PATH into out, through the given VM. False
// leaves the reason in err, named: the file, the key, what it takes.
// Leaves no exception behind and no lasting object in the VM.
bool config_load(mrb_state* mrb, const char* path, Config& out, char* err, size_t errlen);

}  // namespace webmachine

// ------------------------------------------------------------------
// The refusals' own classes. Until now every one of them raised
// RuntimeError - the anonymous catch-all - which made a server's
// refusal indistinguishable from any RuntimeError an app raises
// itself, and left `rescue` no way to mean "webmachine said no".
//
// Three classes, because this tree makes exactly three distinctions:
// a configuration that cannot stand, a route that cannot be built,
// and everything else. More classes than distinctions would be
// decoration. What is genuinely Ruby semantics keeps its Ruby class:
// a TypeError for a wrong return type, a KeyError for a missing key -
// a refusal by the server is a different thing from a mistake in a
// value.
//
// Macros rather than helpers, in the shape the neighbouring gems use
// (mruby-toml's E_TOML_ERROR, mruby-libhydrogen's E_HYDRO_ERROR):
// the lookup is a presym pair and happens only where something is
// already going wrong.


#define E_WM_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Error)))
#define E_WM_CONFIG_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(ConfigError)))
#define E_WM_ROUTE_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(RouteError)))

// ------------------------------------------------------------------
// The reactor: one thread, one io backend (#171: io_uring, or the
// select shim where io_uring cannot be had), every piece of state hung
// off one instance - no globals, so N instances could exist someday,
// though no line here knows about threads.
//
// The Ring knows NOTHING but bytes: bytes arrive, it hands them to its
// App; whatever the App appends to the sink goes back out. HTTP, Ruby,
// echo - all of that lives in an App type, bound at compile time
// (template, zero indirection, no std::function, no virtual).
//
// An App provides:
//   struct Conn { void reset(uint8_t listener, bool packetized); };
//                 per-connection state (reset carries which listener
//                 accepted - the App's key to "whose connection is
//                 this" - and whether that listener is TCP, #147: a
//                 unix listener sits behind a proxy and is never
//                 packetized on this hop)
//   bool feed(Conn&, const char*, size_t, std::string& sink, Plan*);
//        false = close this connection once the sink has drained. The
//        Plan is nullable: the Ring passes one only when it could arm
//        it in this very round (no send in flight, last segment of a
//        recv bundle) - then feed may hand bytes over as segments the
//        same way more() does, and they leave WITH the sink in one
//        sendmsg. A null plan asks for the classic copy/park shape.
//   bool pending(const Conn&) const;
//        does this connection still owe bytes the App has not handed
//        over? Asked before each send: true makes it carry MSG_MORE,
//        so a small head does not go out alone and wait out the peer's
//        delayed ACK.
//   struct Plan { struct Seg { const char* base; size_t off, len; };
//                 static constexpr unsigned kSegs; Seg seg[kSegs];
//                 unsigned nseg; size_t iov_len; size_t byte_cap; };
//        byte_cap is set by the Ring before feed/more: the round's
//        byte bound, from the socket's own free space (SO_MEMINFO).
//        The App builds within it; 0 means unbounded.
//   bool more(Conn&, std::string& sink, Plan&);
//        the delivery continuation (#168): called when the sink has
//        fully drained. The App either appends to the sink, or fills
//        the Plan with SEGMENTS - `base` names bytes that already
//        exist somewhere durable (a mapping, a table built at
//        add_route), a null `base` names a RANGE OF THE SINK at `off`,
//        for a round that has to spell some bytes itself and interleave
//        them with the pointed-at ones (h2's DATA frame headers). An
//        offset, not a pointer, because the sink is still being
//        appended to while the plan is built. The whole round leaves in
//        ONE sendmsg, without a body byte passing through this process.
//        Same close contract as feed. An App without sources appends
//        nothing and returns true.
//   bool timed(const Conn&) const;
//        does this connection carry a source that produces on its OWN
//        schedule rather than in answer to bytes (#102, server-sent
//        events)? The per-second sweep continues such a connection -
//        it asks more() - and the idle clock is not its owner: a
//        stream that says nothing for an hour is doing its job, not
//        hanging. An App without such sources answers false and the
//        sweep is exactly the one compare it already was.
//   void on_tick();                                   once per reactor wake
//   AccessLog* access_log();
//        the App's access-log buffers (accesslog.hpp), or null for an
//        App that never logs. The App FORMATS; the Ring flushes: at
//        the end of every round a filled buffer leaves as one write
//        SQE riding the submit that was happening anyway - zero added
//        syscalls, and io-wq makes the page-cache copy off this
//        thread. The rule the flush serves: every line formatted MUST
//        land - the in-flight buffer is the kernel's until its CQE, a
//        short write resumes, a write error is a named refusal that
//        stops the process rather than a silent hole in the log.
//
// EVERYTHING goes through the ring. The listener is born as a direct
// descriptor (io_uring_prep_socket_direct), bound and set listening by
// ring ops (IORING_OP_BIND/LISTEN, kernel 6.11+ - probed at init, named
// error if absent, no POSIX fallback: one implementation, one path).
// The only classic syscall left is mmap, which is memory, not IO.






// SO_MEMINFO (Linux 4.12) is SOL_SOCKET, which is exactly why it works
// where TCP_INFO does not: io_uring's getsockopt cmd refuses every
// level but SOL_SOCKET. Older libcs may lack the name.
#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif

// Prediction hints ONLY where the taken side is terminal - an exit, a
// raise, a connection's death, an invariant violation. A branch that
// swings naturally at runtime (workload-dependent) carries NO hint: a
// static hint on a swinging branch is a systematic mispredict.
#define WM_LIKELY(x) __builtin_expect(!!(x), 1)
#define WM_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace webmachine {

// Slot count == the sparse direct-descriptor table size: a connection's
// id IS its direct descriptor index, so lookup is an array index. The
// listeners live in the slots behind the connections: listener i sits
// at listener_base_ + i ("more than one app per thread" = more than one
// listener on the one ring).
//
// The COUNT is derived, never guessed (#169): the backend owns
// RLIMIT_NOFILE - it raises soft to hard at init (unprivileged, allowed
// for every process; systemd default is soft 1024 / hard 524288, the
// ceiling for the raise is /proc/sys/fs/nr_open) and takes everything
// the final limit allows, minus a reserve. The kernel checks the sparse
// table size against RLIMIT_NOFILE (measured: limit 1024 -> 1023 slots
// ok, 4096 EMFILE), which is why the raise must come first.
inline constexpr uint32_t kMaxListeners = 16;
// Classic fds the process keeps NEXT TO the fixed table: stdio, the
// ring fd, the stop signalfd, the asset ZIP (#170), and foreign
// in-process code (mruby-c-ares sockets). Connections consume NO fd
// numbers here - multishot_accept_direct lands them in the fixed table
// only - so this is headroom, not arithmetic necessity; under a shim
// backend (#171), where connections ARE process fds, the SAME formula
// holds and the reserve becomes load-bearing. One arithmetic, every
// backend: max_conns = final_limit - kFdReserve - kMaxListeners.
inline constexpr uint32_t kFdReserve = 128;
// The kernel's own cap on a fixed-file table (io_uring/rsrc.c,
// IORING_MAX_FIXED_FILES) - a limit above it must not size the table.
inline constexpr uint32_t kFixedTableKernelMax = 1u << 20;

// The one arithmetic with two consumers: the server sizes itself with
// it here; tools/webmachine-tune.sh (#167) only PRINTS it. extra_slots
// = fixed-table slots something other than connections and listeners
// claims; nothing does today. 0 = the limit leaves no room, a named
// refusal for the caller to spell out.
// The OTHER limit a ring is charged against: its SQ/CQ pages are
// locked memory, accounted per USER. Soft to hard, once, before the
// ring exists - #169's shape for RLIMIT_NOFILE applied here. Failure
// is deliberately silent: not being allowed to raise it is no reason
// not to start, it only means the ring below settles smaller.
inline void raise_memlock() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return;
  if (rl.rlim_cur == rl.rlim_max) return;
  struct rlimit want {rl.rlim_max, rl.rlim_max};
  (void)::setrlimit(RLIMIT_MEMLOCK, &want);
}

inline uint32_t derive_max_conns(uint64_t nofile_limit, uint32_t extra_slots = 0) {
  const uint64_t taken = static_cast<uint64_t>(kFdReserve) + kMaxListeners + extra_slots;
  if (nofile_limit <= taken) return 0;
  uint64_t n = nofile_limit - taken;
  if (n + kMaxListeners + extra_slots > kFixedTableKernelMax) {
    n = kFixedTableKernelMax - kMaxListeners - extra_slots;
  }
  return static_cast<uint32_t>(n);
}

// NEVER PIN THIS PROCESS. It was measured twice and lost twice - the
// older tree deleted every taskset it had ("handing the scheduler one
// core was slower than letting it choose"; a client mask widened
// 2 -> 15 -> 30 cpus raised throughput monotonically in the MEDIAN).
// And whenever io_uring hands work to an io-wq worker, that worker
// INHERITS the issuing thread's affinity: pinning locks the pool that
// exists to use OTHER cores onto the core the loop already occupies.
// Measured here at its worst, back when file bodies went through
// splice: 0.07x under `taskset -c 0`, the system at 49.3% sy against
// 10.3% us.
//
// Pool geometry measured in the old tree as not moving the profile
// (2048 x 4096 vs ladders: null result), so the simple shape stays.
inline constexpr uint32_t kBufCount = 2048;
inline constexpr uint32_t kBufSize = 4096;
inline constexpr uint16_t kBufGroup = 0;
static_assert((kBufCount & (kBufCount - 1)) == 0, "buffer walk wraps by mask");
static_assert(static_cast<size_t>(kBufCount) <= SIZE_MAX / kBufSize,
              "pool size arithmetic must not overflow");

// #169's raise: soft to hard, ceiling fs.nr_open - done ONCE at init,
// and the capacity falls out of whatever finally stands.
//
// Which of the two paths below runs is decided by a PROPERTY the
// liburing.h on this include path states, never by which
// implementation it is (#171). IO_URING_FD_CEILING means "every
// descriptor handed to these functions must stay strictly below this
// number"; its ABSENCE means the API imposes no ceiling and the
// process rlimits are the only bound. Asking WHO answered instead
// would hand select's FD_SETSIZE to every implementation that comes
// later - an IOCP build has no fd_set at all - so this file never
// learns a name.
inline uint64_t raise_nofile() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
#ifdef IO_URING_FD_CEILING
  // The API states a ceiling, so descriptors are what it counts: here a
  // connection IS a process fd, and the rlimit is the only thing that
  // keeps fd numbers under that roof - for this process AND for every
  // neighbour holding an fd_set, mruby-c-ares being the concrete one.
  // The soft limit is moved TO that roof - down where it stood higher,
  // up where it stood lower - so the two agree, once, at init.
  rlim_t target = static_cast<rlim_t>(IO_URING_FD_CEILING - 1);
  if (target > rl.rlim_max) target = rl.rlim_max;
  if (rl.rlim_cur != target) {
    struct rlimit want {target, rl.rlim_max};
    (void)::setrlimit(RLIMIT_NOFILE, &want);
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
  }
  const uint64_t cur = static_cast<uint64_t>(rl.rlim_cur);
  return cur < IO_URING_FD_CEILING ? cur : IO_URING_FD_CEILING - 1;
#else
  // No ceiling stated: nothing but the rlimits bounds this. With the
  // real ring, connections live in the fixed-file table and consume no
  // fd numbers, so take everything the hard limit allows, ceiling
  // fs.nr_open. #169 measured why a cap would only cost here.
  rlim_t target = rl.rlim_max;
  if (target == RLIM_INFINITY) {
    uint64_t nr_open = 1u << 20;  // kernel default; used only if /proc is unreadable
    if (std::FILE* f = std::fopen("/proc/sys/fs/nr_open", "re")) {
      unsigned long long v = 0;
      if (std::fscanf(f, "%llu", &v) == 1 && v > 0) nr_open = v;
      std::fclose(f);
    }
    target = static_cast<rlim_t>(nr_open);
  }
  if (rl.rlim_cur < target) {
    struct rlimit want {target, rl.rlim_max};
    (void)::setrlimit(RLIMIT_NOFILE, &want);
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
  }
  return static_cast<uint64_t>(rl.rlim_cur);
#endif
}

// One listener: exactly one of unix_path / port.
struct ListenerSpec {
  const char* unix_path = nullptr;
  int port = 0;
};

struct RingConfig {
  ListenerSpec listeners[kMaxListeners] = {};
  uint32_t nlisteners = 0;
  // The access log's fd (O_APPEND), or -1 for no log. main owns the
  // open; the Ring owns every write.
  int log_fd = -1;
  // #166 tunables, setup-only reads. The defaults are the tree's own
  // measured choices; a config file may override them, and 0 means
  // "the default" so an uninitialized field cannot smuggle a zero
  // into the kernel.
  unsigned sq_entries = 0;  // first ask of the halving SQ init (default 32768)
  int backlog = 0;          // listen(2) backlog (default 511)
  // The three timeout clocks, in seconds; 0 = the nginx-twin defaults
  // every server converged on. header is TOTAL for a request head
  // (the Slowloris brake), send is BETWEEN progresses, idle is the
  // keep-alive quiet time (75 is nginx's "we talk to browsers
  // directly" number; Apache/Node's 5 is the behind-a-proxy world).
  int to_header = 0;  // default 60
  int to_send = 0;    // default 60
  int to_idle = 0;    // default 75
  // A signalfd main owns (signals blocked, so they land there). The
  // ring polls it: the stop signal arrives as a CQE like everything
  // else - a handler flag would race the wait (checked, then the signal
  // lands, then the wait blocks forever with the flag set).
  int stop_fd = -1;
};

namespace detail {

// user_data: kind(8) | gen(16) | idx(32). gen guards a reused slot
// against CQEs of the connection that owned it before.
enum : uint8_t {
  kAccept = 1, kRecv = 2, kSend = 3, kClose = 4, kSetup = 5, kStop = 6, kShutdown = 7,
  kMeminfo = 8, kLog = 9, kPeer = 10
};

inline uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
}

// The setup chain's stages, carried in the idx half of the tag so a
// failing CQE can name what failed.
enum : uint32_t { kStSocket = 1, kStSockopt = 2, kStBind = 3, kStListen = 4, kStName = 5 };

inline const char* stage_name(uint32_t st) {
  switch (st) {
    case kStSocket: return "socket";
    case kStSockopt: return "setsockopt";
    case kStBind: return "bind";
    case kStListen: return "listen";
    case kStName: return "getsockname";
  }
  return "?";
}

}  // namespace detail

// Io picks the backend (#171): UringIo by default, SelectIo as the
// portable/lazy path - two instantiations, zero indirection in
// either, the one branch point living in main at init.
template <class App>
class Ring {
 public:
  explicit Ring(App& app) : app_(app) {}
  Ring(const Ring&) = delete;
  Ring& operator=(const Ring&) = delete;

  ~Ring() {
    if (ring_up_) {
      // The listeners leave through the ring like everything else did,
      // and a unix listener takes its path with it - waited on, because
      // queue_exit would race the unlink.
      close_listeners();
      unsigned n = 0;
      for (const std::string& path : unix_paths_) {
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) break;
        io_uring_prep_unlink(s, path.c_str(), 0);
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, 0));
        n++;
      }
      if (n != 0) io_uring_submit_and_wait(&ring_, n);
    }
    if (buf_ring_ != nullptr) io_uring_free_buf_ring(&ring_, buf_ring_, kBufCount, kBufGroup);
    if (pool_ != nullptr) ::munmap(pool_, static_cast<size_t>(kBufCount) * kBufSize);
    if (ring_up_) io_uring_queue_exit(&ring_);
  }

  // False leaves the reason - naming the failed setup stage - in err.
  // Reads WM_BUNDLE, the one env knob left and only ever narrowing:
  // recv bundles default to the kernel's feature bit, and one
  // known-broken kernel (container 6.18.5-fc) violates the dense-fill
  // contract and needs WM_BUNDLE=0. It earns its place by answering a
  // correctness question no build-time check can.
  // EVERY failure here is this machine refusing this configuration - a
  // taken port, an fd limit that leaves no room. Which io_uring answers
  // these calls was settled at BUILD time (src/uring.hpp), so nothing
  // in here is a reason to go looking for another one: a bind clash
  // that silently demoted the server to a slower path would be a
  // performance cliff wearing a startup message.
  bool init(const RingConfig& cfg, char* err, size_t errlen) {
    int rc = 0;
    // The SQ is a SHARED, fixed resource - every in-flight operation of
    // every connection sits in it, and one response can claim many
    // (a body split into frames is one SQE per segment). 32768 is the
    // kernel's own ceiling, IORING_MAX_ENTRIES; the SQ array costs
    // 64 bytes an entry and the CQ 16 at twice the count, so the full
    // ask is ~3 MiB once per process.
    //
    // A machine that will not give that gets less, not a refusal: a
    // smaller ring is smaller HEADROOM, not a wrong ring, and the same
    // rule already governs max_conns_ ("the capacity falls out of
    // whatever finally stands", #169). Halve until one takes; the
    // floor is what stood here before this loop existed, so this can
    // only ever end at least as well as it used to.
    raise_memlock();
    constexpr unsigned kSqWanted = 32768;
    constexpr unsigned kSqFloor = 1024;
    constexpr unsigned kSetupFlags =
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    // A configured ask below the floor IS the floor for this run: the
    // operator asked for a small ring on purpose, one try, named
    // refusal if the machine will not even give that.
    const unsigned sq_wanted = cfg.sq_entries != 0 ? cfg.sq_entries : kSqWanted;
    const unsigned sq_floor = sq_wanted < kSqFloor ? sq_wanted : kSqFloor;
    struct io_uring_params p {};
    for (sq_entries_ = sq_wanted;; sq_entries_ /= 2) {
      // queue_init_params WRITES its result into p (sq/cq entries,
      // features), so a retry starts from a clean one.
      p = io_uring_params{};
      p.flags = kSetupFlags;
      rc = io_uring_queue_init_params(sq_entries_, &ring_, &p);
      if (rc == 0) {
        sq_entries_ = p.sq_entries;  // what the KERNEL gave, not what was asked
        break;
      }
      if (sq_entries_ <= sq_floor) {
        std::snprintf(err, errlen, "io_uring_queue_init(%u): %s", sq_entries_,
                      std::strerror(-rc));
        return false;
      }
    }
    // One fewer fd-table lookup per enter(2); nothing else shares this fd.
    io_uring_register_ring_fd(&ring_);
    ring_up_ = true;

    // The limit is set ONCE, here, and never touched again. The
    // capacity falls out of whatever finally stands.
    const uint64_t nofile = raise_nofile();
    log_fd_ = cfg.log_fd;
    backlog_ = cfg.backlog != 0 ? cfg.backlog : 511;
    to_header_ = cfg.to_header != 0 ? cfg.to_header : 60;
    to_send_ = cfg.to_send != 0 ? cfg.to_send : 60;
    to_idle_ = cfg.to_idle != 0 ? cfg.to_idle : 75;
    max_conns_ = derive_max_conns(nofile);
    if (max_conns_ == 0) {
      std::snprintf(err, errlen,
                    "RLIMIT_NOFILE %llu leaves no room for connections "
                    "(reserve %u + listeners %u)",
                    static_cast<unsigned long long>(nofile), kFdReserve, kMaxListeners);
      return false;
    }
    listener_base_ = max_conns_;

    rc = io_uring_register_files_sparse(&ring_, max_conns_ + kMaxListeners);
    if (rc != 0) {
      std::snprintf(err, errlen, "register_files_sparse(%u): %s",
                    max_conns_ + kMaxListeners, std::strerror(-rc));
      return false;
    }
    // The direct-descriptor allocator's cursor continues past the last
    // slot it touched - after the listeners land at listener_base_+ the
    // next accept would be handed a LISTENER slot (measured: res=4097).
    // Confine allocation to the connection slots; listeners are placed,
    // never allocated.
    rc = io_uring_register_file_alloc_range(&ring_, 0, max_conns_);
    if (rc != 0) {
      std::snprintf(err, errlen, "register_file_alloc_range: %s", std::strerror(-rc));
      return false;
    }

    const size_t pool_bytes = static_cast<size_t>(kBufCount) * kBufSize;  // static_assert-bounded
    void* mem =
        ::mmap(nullptr, pool_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
      std::snprintf(err, errlen, "mmap pool: %s", std::strerror(errno));
      return false;
    }
    pool_ = static_cast<char*>(mem);

    int bre = 0;
    buf_ring_ = io_uring_setup_buf_ring(&ring_, kBufCount, kBufGroup, 0, &bre);
    if (buf_ring_ == nullptr) {
      std::snprintf(err, errlen, "setup_buf_ring: %s", std::strerror(-bre));
      return false;
    }
    // Written once. Replenish is advance-only: the kernel consumes entries
    // strictly in ring order, so re-exposing a slot re-exposes the buffer
    // it has always named.
    const int mask = io_uring_buf_ring_mask(kBufCount);
    for (uint32_t i = 0; i < kBufCount; i++) {
      io_uring_buf_ring_add(buf_ring_, pool_ + static_cast<size_t>(i) * kBufSize, kBufSize,
                            static_cast<uint16_t>(i), mask, static_cast<int>(i));
    }
    io_uring_buf_ring_advance(buf_ring_, kBufCount);

    // Default: the kernel's own feature bit. WM_BUNDLE=0 narrows, for the
    // one kernel caught violating the dense-fill contract (6.18.5-fc:
    // res spanned buffers each holding only its own small segment).
    bundles_ = (ring_.features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
    if (const char* e = std::getenv("WM_BUNDLE")) {
      if (e[0] == '0') bundles_ = false;
    }

    if (cfg.nlisteners == 0 || cfg.nlisteners > kMaxListeners) {
      std::snprintf(err, errlen, "listener count %u out of range (1..%u)", cfg.nlisteners,
                    kMaxListeners);
      return false;
    }
    for (uint32_t li = 0; li < cfg.nlisteners; li++) {
      if (!setup_listener(li, cfg.listeners[li], err, errlen)) return false;
    }
    nlisteners_ = cfg.nlisteners;

    // One allocation at init, sized by the derived capacity - memory now
    // scales with the limit (a half-million-fd host pays tens of MB
    // here). Deliberate: no guessed cap anywhere; #166 makes it
    // overridable, and an override ABOVE the derivation is refused by
    // name there, never silently clamped.
    conns_.resize(max_conns_);
    rearm_.reserve(64);

    if (cfg.stop_fd >= 0) {
      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_poll_add(s, cfg.stop_fd, POLLIN);
      io_uring_sqe_set_data64(s, detail::tag(detail::kStop, 0, 0));
    }

    for (uint32_t li = 0; li < nlisteners_; li++) arm_accept(li);
    return true;
  }

  // Loops until the stop_fd CQE lands, then returns so the destructor
  // runs: that is what removes the unix socket path again.
  void run() {
    while (!stop_) tick(nullptr);
  }

  // ONE bounded step (#116 slice 3, Gebot 18 as an API): with a budget
  // the WAIT is at most that long AND the batch is interrupted between
  // completions once it is spent - what is left stays in the CQ and the
  // next tick continues it. Without one this is the loop's own step:
  // block until at least one completion, then drain the batch.
  // True = work was processed.
  bool tick(const struct __kernel_timespec* budget) {
    if (budget == nullptr) return step(nullptr, false);
    // The deadline is read ONCE here and compared between completions
    // against the coarse monotonic clock - a vDSO read, no syscall.
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    int64_t deadline = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
    deadline += budget->tv_sec * 1000000000 + budget->tv_nsec;
    return step(&deadline, true);
  }

  // The descriptor an embedder polls (#116 slice 3): readable exactly
  // when this ring has completions to hand over, so an idle server
  // costs its host nothing. -1 before init.
  int fd() const { return ring_up_ ? ring_.ring_fd : -1; }

  // Did the stop signal's completion land? The bounded tick's caller
  // owns its own loop and has to be able to ask.
  bool stopped() const { return stop_; }

  // DRAIN, THEN FORGET (#116 slice 5). The listeners close at once -
  // nothing new is taken - and the loop keeps turning until either the
  // last accepted connection is gone or the grace runs out, whichever
  // comes first. Grace 0 means the second condition is already true,
  // which is the immediate stop.
  //
  // The connections that survive the grace are FORGOTTEN, not waited
  // on: an idle keep-alive peer that says nothing would otherwise hold
  // the process open forever, and it is the destructor's ring exit that
  // ends them - one place, the same place a signal's stop uses.
  void drain(int64_t grace_ns) {
    if (draining_) return;
    draining_ = true;
    close_listeners();
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    drain_deadline_ = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec + grace_ns;
    if (live_ == 0 || grace_ns <= 0) stop_ = true;
  }

  // How many accepted connections are still being served. The drain
  // watches it; a caller with its own loop can too.
  uint32_t live_conns() const { return live_; }

  // The derived capacity - what the machine actually allows, the "thing
  // that says what max is". tools/webmachine-tune.sh prints the same
  // arithmetic without running a server.
  uint32_t max_conns() const { return max_conns_; }

  // A TCP listener's REAL port once init returned: the configured one,
  // or - for a port-0 ask - the kernel's pick, read back at setup.
  int bound_port(uint32_t li) const { return li < kMaxListeners ? bound_port_[li] : 0; }

 private:
  // One listener, made entirely of ring ops: a stale unix path goes
  // first and UNLINKED from the chain (a linked op that fails - ENOENT
  // is normal - would cancel everything behind it), then socket ->
  // (setsockopt) -> bind -> listen as one linked chain, one submit,
  // every CQE checked, a failure naming its stage.
  bool setup_listener(uint32_t li, const ListenerSpec& spec, char* err, size_t errlen) {
    const uint32_t slot = listener_base_ + li;
    const bool is_unix = spec.unix_path != nullptr;
    struct sockaddr_un sun {};
    struct sockaddr_in sin {};
    struct sockaddr* sa = nullptr;
    socklen_t salen = 0;
    if (is_unix) {
      sun.sun_family = AF_UNIX;
      const size_t plen = std::strlen(spec.unix_path);
      if (plen >= sizeof(sun.sun_path)) {
        std::snprintf(err, errlen, "listener %u: unix path too long (%zu)", li, plen);
        return false;
      }
      std::memcpy(sun.sun_path, spec.unix_path, plen + 1);
      sa = reinterpret_cast<struct sockaddr*>(&sun);
      salen = sizeof(sun);

      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) {
        std::snprintf(err, errlen, "SQ empty at setup");
        return false;
      }
      io_uring_prep_unlink(s, spec.unix_path, 0);
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, 0));
      io_uring_submit_and_wait(&ring_, 1);
      struct io_uring_cqe* cqe = nullptr;
      if (io_uring_peek_cqe(&ring_, &cqe) == 0) {
        // Only ENOENT is ordinary; anything else on the path is a refusal.
        if (cqe->res < 0 && cqe->res != -ENOENT) {
          std::snprintf(err, errlen, "unlink %s: %s", spec.unix_path, std::strerror(-cqe->res));
          return false;
        }
        io_uring_cqe_seen(&ring_, cqe);
      }
    } else {
      // 0 is legal here: "the OS picks", and the pick is read back off
      // the bound listener below.
      if (spec.port < 0 || spec.port > 65535) {
        std::snprintf(err, errlen, "listener %u: port %d out of range", li, spec.port);
        return false;
      }
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl(INADDR_ANY);
      sin.sin_port = htons(static_cast<uint16_t>(spec.port));
      sa = reinterpret_cast<struct sockaddr*>(&sin);
      salen = sizeof(sin);
    }

    // The addresses live on this frame; init blocks until the chain's
    // CQEs, so the borrow ends before the frame does.
    static const int kOne = 1;  // static: SO_REUSEADDR optval, borrowed by the ring op
    unsigned chain = 0;
    {
      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_socket_direct(s, is_unix ? AF_UNIX : AF_INET, SOCK_STREAM, 0, slot, 0);
      s->flags |= IOSQE_IO_LINK;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStSocket));
      chain++;

      if (!is_unix) {
        s = io_uring_get_sqe(&ring_);
        if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
        io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, slot, SOL_SOCKET, SO_REUSEADDR,
                               const_cast<int*>(&kOne), sizeof(kOne));
        s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStSockopt));
        chain++;
      }

      s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_bind(s, slot, sa, salen);
      s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStBind));
      chain++;

      s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      // 511 is the shared default half the servers on the net use
      // (nginx's own); somaxconn still caps it silently, which
      // tools/webmachine-tune.sh points out on the machine itself.
      io_uring_prep_listen(s, slot, backlog_);
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStListen));
      chain++;
    }
    io_uring_submit_and_wait(&ring_, chain);
    {
      bool failed = false;
      struct io_uring_cqe* cqe = nullptr;
      while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
        if (cqe->res < 0 && !failed) {
          // -ECANCELED names the victim of an earlier failure, not a cause.
          if (cqe->res != -ECANCELED) {
            const uint32_t st = static_cast<uint32_t>(io_uring_cqe_get_data64(cqe));
            std::snprintf(err, errlen, "listener %u %s: %s", li, detail::stage_name(st),
                          std::strerror(-cqe->res));
            failed = true;
          } else if (err[0] == '\0') {
            std::snprintf(err, errlen, "listener %u: setup chain canceled", li);
            failed = true;
          }
        }
        io_uring_cqe_seen(&ring_, cqe);
      }
      if (failed) return false;
    }
    // Only a bind that happened leaves a path to remove again.
    if (is_unix) unix_paths_.emplace_back(spec.unix_path);
    // TCP-only settings (TCP_NODELAY, SO_SNDBUF) are asked per accept;
    // a connection remembers which listener took it.
    unix_listener_[li] = is_unix;

    if (!is_unix) {
      bound_port_[li] = spec.port;
      if (spec.port == 0) {
        // The OS picked; ask the BOUND listener its local name - the
        // same URING_CMD %h rides at accept (arm_peer), local form
        // (optlen 0) instead of peer (1). Slice 2 refused port 0
        // because "io_uring has no getsockname"; the cmd exists now
        // and this is its second customer. A kernel without it turns
        // ONLY a port-0 ask into a named refusal - fixed ports never
        // ask the question.
        struct sockaddr_storage ss {};
        int slen = static_cast<int>(sizeof(ss));
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
        io_uring_prep_rw(IORING_OP_URING_CMD, s, static_cast<int>(slot), nullptr, 0, 0);
        s->cmd_op = SOCKET_URING_OP_GETSOCKNAME;
        s->addr = reinterpret_cast<uint64_t>(&ss);
        s->optval = reinterpret_cast<uint64_t>(&slen);
        s->optlen = 0;  // the LOCAL name; 1 is the peer form
        s->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStName));
        io_uring_submit_and_wait(&ring_, 1);
        struct io_uring_cqe* cqe = nullptr;
        int res = -EIO;
        if (io_uring_peek_cqe(&ring_, &cqe) == 0) {
          res = cqe->res;
          io_uring_cqe_seen(&ring_, cqe);
        }
        if (res < 0) {
          std::snprintf(err, errlen,
                        "listener %u: port 0 needs the bound port read back and this kernel "
                        "cannot (SOCKET_URING_OP_GETSOCKNAME: %s) - name a port",
                        li, std::strerror(-res));
          return false;
        }
        if (ss.ss_family == AF_INET) {
          bound_port_[li] = ntohs(reinterpret_cast<struct sockaddr_in*>(&ss)->sin_port);
        } else if (ss.ss_family == AF_INET6) {
          bound_port_[li] = ntohs(reinterpret_cast<struct sockaddr_in6*>(&ss)->sin6_port);
        } else {
          std::snprintf(err, errlen, "listener %u: bound name family %d?", li,
                        static_cast<int>(ss.ss_family));
          return false;
        }
      }
    }
    return true;
  }

  struct Conn {
    // Read on every event before anything else.
    bool live = false;
    bool sending = false;          // `out` is borrowed by the kernel
    bool close_after_send = false;
    // The timeout clock (#180). idle marks a connection owing nothing
    // (between requests); deadline_s is the coarse second this
    // connection dies at unless something moves it. Transitions:
    // accept and idle->first-byte set now+header (TOTAL for the head -
    // later recvs do NOT extend it, that is the Slowloris brake), a
    // send's progress sets now+send, a full drain with nothing owed
    // sets now+idle. Priced: one store on paths that already run.
    // KNOWN EDGE, stated not hidden: a peer that only ever SENDS
    // (streaming upload, a websocket client that pushes and never
    // hears) dies at the header clock unless the server writes
    // something back within it - revisit when #165 gives bodies a
    // consumer and #175's websocket tier answers pings.
    bool idle = false;
    int64_t deadline_s = 0;
    uint8_t li = 0;    // which listener accepted - the App's key
    uint16_t gen = 0;  // stale-CQE guard: slot reuse bumps it, old ops miss
    size_t sent = 0;   // bytes of `out` the kernel has taken so far

    // The round's byte bound, from the socket's own books (SO_MEMINFO:
    // sndbuf minus queued, the arithmetic sk_stream_wspace uses - the
    // SIOCOUTQ route was measured and buried, it counts payload while
    // admission counts truesize). Refreshed by a getsockopt riding the
    // batch whenever a drained send leaves work pending; until the
    // first answer lands, a conservative floor. `mi` is the kernel's
    // landing pad and must be stable memory, which is why it lives
    // here.
    static constexpr size_t kRoundFloor = 64u * 1024;
    size_t round_cap = kRoundFloor;
    uint32_t mi[SK_MEMINFO_VARS] = {};
    // The peer's RAW sockaddr, for the access log alone - fetched at
    // accept through the ring (SOCKET_URING_OP_GETSOCKNAME, peer form)
    // and only when a log is on. The server never formats it; the
    // record ships these bytes and webmachine-logd spells them, at
    // whatever privacy level the operator chose. Both fields are the
    // kernel's landing pad and must be stable memory.
    struct sockaddr_storage peer_ss;
    int peer_slen = 0;

    // Two buffers, not one: `out` is BORROWED by an in-flight send (its
    // pointer is in the SQE), so nothing may append to or clear it until
    // the send's CQE - appends land in `next`, the swap happens when the
    // send drains. Capacity survives clear(); a warm slot allocates
    // nothing.
    std::string out;
    std::string next;

    // One MORE than the plan can hold: a plan of pure pointers leaves
    // the sink to be sent ahead of it, and that prepend must always
    // have somewhere to go. Truncating instead would drop bytes off
    // the wire silently, which is the one failure this model must not
    // be able to have.
    static constexpr unsigned kIov = App::Plan::kSegs + 1;
    unsigned niov = 0;    // 0 = plain send of `out`
    size_t plan_len = 0;  // total bytes across iov
    struct msghdr msg {};

    // The App's per-connection state; the Ring only resets it.
    typename App::Conn app;

    // The App's PLAN for one round (#168), resolved: pointers into a
    // mapping or into a table built at add_route, interleaved with
    // ranges of `out` where the round had to spell bytes itself (h2's
    // DATA frame headers). One sendmsg puts the whole round on the
    // wire without a single body byte passing through this process.
    // They must live until the CQE, which is why they hang off the
    // Conn and not a stack frame. msg_iov is what the in-flight
    // sendmsg actually points at - iov minus whatever a partial send
    // consumed - kept separate so the plan stays intact across
    // retries.
    //
    // ON THE HEAP, LAZILY: at kIov = 1024 (IOV_MAX) the pair is 32 KB,
    // and conns_ holds max_conns_ slots (RLIMIT_NOFILE-derived, easily
    // a million). A connection that never hands over a plan - every
    // idle one, every hello - pays two null pointers; the first plan
    // allocates once and the block stays for the slot's lifetime, warm
    // like the strings above.
    std::unique_ptr<struct iovec[]> iov;
    std::unique_ptr<struct iovec[]> msg_iov;
  };

  // Never returns null: a full SQ is submitted and retried once, and a
  // ring that cannot take an SQE after that is a broken ring - checked,
  // reported on stderr, process exits (there is no connection to blame).
  struct io_uring_sqe* sqe() {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (WM_LIKELY(s != nullptr)) return s;
    io_uring_submit(&ring_);
    s = io_uring_get_sqe(&ring_);
    if (WM_UNLIKELY(s == nullptr)) {
      std::fprintf(stderr, "webmachine: SQ (%u entries) stuck after submit; ring is broken\n",
                   sq_entries_);
      std::exit(1);
    }
    return s;
  }

  // The access-log flush (see the contract block up top). Called once
  // per round, right before the submit the SQE rides.
  void flush_log() {
    if (log_fd_ < 0) return;
    AccessLog* al = app_.access_log();
    if (al == nullptr || al->in_flight || al->buf.empty()) return;
    al->buf.swap(al->flight);
    al->in_flight = true;
    arm_log_write(al);
  }
  void arm_log_write(AccessLog* al) {
    struct io_uring_sqe* s = sqe();
    // send, not write: the log fd is the daemon's socketpair, and a
    // dead daemon must come back as -EPIPE in the CQE (the named
    // refusal in on_log), not as a SIGPIPE that kills silently.
    io_uring_prep_send(s, log_fd_, al->flight.data(), al->flight.size(), MSG_NOSIGNAL);
    io_uring_sqe_set_data64(s, detail::tag(detail::kLog, 0, 0));
  }
  void on_log(struct io_uring_cqe* cqe) {
    AccessLog* al = app_.access_log();
    if (al == nullptr) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      // THE RULE: every line formatted lands. A log the disk refuses
      // is a promise this process can no longer keep - refuse by name
      // instead of dropping silently.
      std::fprintf(stderr, "webmachine: access log write failed: %s - refusing to drop lines\n",
                   std::strerror(-cqe->res));
      std::exit(1);
    }
    const size_t took = static_cast<size_t>(cqe->res);
    if (WM_UNLIKELY(took < al->flight.size())) {
      al->flight.erase(0, took);
      arm_log_write(al);  // the remainder still lands; rides the next submit
      return;
    }
    al->flight.clear();
    al->in_flight = false;
  }

  // The listeners leave through the ring, like everything else. Called
  // by drain and by the destructor, which is why it is idempotent -
  // closing a slot twice would take a slot a later accept was given.
  void close_listeners() {
    if (listeners_closed_) return;
    listeners_closed_ = true;
    for (uint32_t i = 0; i < nlisteners_; i++) {
      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) break;
      io_uring_prep_close_direct(s, listener_base_ + i);
      io_uring_sqe_set_data64(s, detail::tag(detail::kClose, 0, listener_base_ + i));
    }
    io_uring_submit(&ring_);
  }

  void arm_accept(uint32_t li) {
    if (draining_) return;  // nothing new is taken once the drain began
    struct io_uring_sqe* s = sqe();
    io_uring_prep_multishot_accept_direct(s, listener_base_ + li, nullptr, nullptr, 0);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kAccept, 0, li));
  }

  void arm_recv(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
    s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    s->buf_group = kBufGroup;
    if (bundles_) s->ioprio |= IORING_RECVSEND_BUNDLE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
  }

  // MSG_MORE when the App still owes bytes behind this segment: a
  // response is head-then-body, and a lone small head goes out and
  // then WAITS for the peer's delayed ACK before the body may follow
  // (measured in the previous tree: 44.30ms average, 1,118 req/s ->
  // 31,077 once fixed). MSG_MORE rather than TCP_CORK deliberately -
  // cork is connection state that needs an uncork afterwards, so a
  // response failing between head and body would leave the connection
  // corked; MSG_MORE is an argument to this one send and cannot
  // outlive it.
  void arm_send(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    const int flags = MSG_NOSIGNAL | (app_.pending(c.app) ? MSG_MORE : 0);
    if (c.niov == 0) {
      io_uring_prep_send(s, static_cast<int>(idx), c.out.data() + c.sent,
                         c.out.size() - c.sent, flags);
    } else {
      // A PLAN: head plus pointers into the mapping, one operation, no
      // copy in this process. The iovecs are rebuilt from `sent` each
      // time because a partial send may have consumed whole segments
      // and part of the next - the kernel takes what the socket has
      // room for and says how much.
      //
      // MSG_SPLICE_PAGES WAS TRIED HERE AND DOES NOTHING (measured,
      // 6.18, io_uring): it is an MSG_INTERNAL_SENDMSG_FLAGS bit meant
      // for in-kernel callers whose iterators are already bvec/kvec; a
      // userspace iovec does not qualify. 2 GiB in 256 KiB chunks over
      // loopback, flag on against flag off, three rounds each: 2001 /
      // 2025 / 2147 MB/s against 2158 / 2064 / 2080, with system time
      // equal to three decimals - no saved copy, in either direction.
      // A second probe confirms it from the other side: clobbering the
      // source buffer immediately after io_uring_submit still puts the
      // ORIGINAL bytes on the wire, i.e. the copy already happened.
      // Which is also the standing rule for every send here - anything
      // that fits in the sndbuf (3.76 MiB on loopback TCP, 208 KiB on
      // AF_UNIX) is the kernel's the moment submit returns.
      //
      // That leaves ONE kernel copy per body and nothing to remove.
      // The alternatives both cost more than they save and are closed:
      // splice needs a pipe, a second operation and an io-wq hop
      // (measured 0.63x-0.79x at 256 KiB / 1 MiB); SEND_ZC buys the
      // copy back with a ubuf_info and a SECOND completion per send,
      // and caps in-flight bytes at the RLIMIT_MEMLOCK account (~8 MB)
      // - a great deal of bookkeeping around a small window.
      unsigned n = 0;
      size_t skip = c.sent;
      for (unsigned i = 0; i < c.niov; i++) {
        if (skip >= c.iov[i].iov_len) {
          skip -= c.iov[i].iov_len;
          continue;
        }
        c.msg_iov[n].iov_base = static_cast<char*>(c.iov[i].iov_base) + skip;
        c.msg_iov[n].iov_len = c.iov[i].iov_len - skip;
        skip = 0;
        n++;
      }
      c.msg = msghdr{};
      c.msg.msg_iov = c.msg_iov.get();
      c.msg.msg_iovlen = n;
      io_uring_prep_sendmsg(s, static_cast<int>(idx), &c.msg, flags);
    }
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kSend, c.gen, idx));
    c.sending = true;
  }

  void begin_close(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.live) return;
    // An in-flight send borrows c.out and the plan's pointers; the slot
    // may not be reset (and the descriptor not closed) until its CQE
    // lands - on_send finishes the close.
    if (c.sending) {
      c.close_after_send = true;
      return;
    }
    c.live = false;
    if (live_ != 0) live_--;
    // The armed multishot recv holds a file reference: close_direct alone
    // only clears the table slot, the socket stays open and the peer
    // never sees FIN (three bintests hung exactly there). shutdown forces
    // the FIN out first; the link keeps the order. Both SQEs must ride
    // the same submission or the link breaks.
    if (io_uring_sq_space_left(&ring_) < 2) io_uring_submit(&ring_);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_shutdown(s, static_cast<int>(idx), SHUT_RDWR);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kShutdown, c.gen, idx));
    s = sqe();
    io_uring_prep_close_direct(s, idx);
    io_uring_sqe_set_data64(s, detail::tag(detail::kClose, c.gen, idx));
  }

  void on_accept(uint32_t li, struct io_uring_cqe* cqe) {
    if (!(cqe->flags & IORING_CQE_F_MORE)) arm_accept(li);
    if (cqe->res < 0) return;  // transient (EMFILE and friends); multishot may carry on
    const uint32_t idx = static_cast<uint32_t>(cqe->res);
    if (WM_UNLIKELY(idx >= max_conns_)) return;  // the kernel named a slot we never registered
    Conn& c = conns_[idx];
    c.gen++;
    c.live = true;
    live_++;
    c.sending = false;
    c.close_after_send = false;
    c.idle = false;
    c.deadline_s = now_s_ + to_header_;  // the whole first head, within this
    c.li = static_cast<uint8_t>(li);
    c.sent = 0;
    c.out.clear();  // capacity survives: a warm slot allocates nothing
    c.next.clear();
    c.app.reset(static_cast<uint8_t>(li), !unix_listener_[li]);  // whose listener, whose app, packetized?
    // A server that writes complete responses has nothing for Nagle to
    // coalesce - only stalls to offer. Found the hard way (#168): a
    // response whose tail went out as its own small segment waited
    // ~43ms for the peer's delayed ACK, once per response. Best effort
    // through the ring; the CQE is ignored (kSetup has no handler arm,
    // deliberately).
    if (!unix_listener_[li]) {
      static const int kOne = 1;
      struct io_uring_sqe* s = sqe();
      io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx),
                             IPPROTO_TCP, TCP_NODELAY, const_cast<int*>(&kOne), sizeof(kOne));
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, idx));
      // TCP_MAXSEG once lived here too (#147), queried per connection
      // to gate gzip on the real segment size. Retired (Nutzer-Entscheid
      // 2026-08-22, #147 Tor 1 revision): io_uring_cmd_getsockopt
      // (io_uring/cmd_net.c) hard-refuses every level but SOL_SOCKET -
      // TCP_MAXSEG is IPPROTO_TCP, so it was structurally unreachable
      // through the ring by any op, confirmed live as -EOPNOTSUPP. The
      // only bridge was IORING_OP_FIXED_FD_INSTALL + getsockopt(2) +
      // close(2), linked ahead of the first recv so the query always
      // landed before a response could be built - a whole extra ring
      // round-trip of latency on every TCP accept, paid before the
      // connection had said a word. http1.hpp's kCompressFloor replaces
      // the query with a fixed floor (1280B, the IPv6 minimum MTU) that
      // needs nothing from the kernel at accept time.
    }
    // The first response should not run on the blind floor: the
    // meminfo lands with this same batch, long before the peer's
    // first request arrives.
    arm_meminfo(idx);
    // The peer's address for the log, same batch - its cmd completes
    // inline at submit while the first recv still waits on the wire,
    // so even the first request's line carries it. Only when someone
    // is logging: without a log the bytes have no reader.
    if (log_fd_ >= 0 && !unix_listener_[li]) arm_peer(idx);
    arm_recv(idx);
  }

  void on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;  // a previous tenant's completion

    if (WM_UNLIKELY(cqe->res <= 0)) {
      if (cqe->res == -ENOBUFS) {
        // Reachable by arithmetic: max_conns_ (derived; in practice far
        // above kBufCount's 2048 since #169), and every completion
        // consumes at least one whole buffer no
        // matter how few bytes it carries. Under DEFER_TASKRUN all
        // completions of a wait window are produced before userspace runs
        // again, and buffers only return at the NEXT tick's advance - so
        // >2048 readable connections in one window (or one bundle burst
        // past 8 MiB) drain the pool and the rest post ENOBUFS. Without
        // this re-arm their multishot is dead and the connection hangs.
        rearm_.push_back(idx);
        return;
      }
      // 0 = EOF; everything else ends the connection the same way.
      begin_close(idx);
      return;
    }
    // Between requests the first byte opens the header clock; while a
    // head is being received, later bytes deliberately do NOT touch it
    // (the clock is TOTAL for the head - Conn's comment says why).
    if (c.idle) {
      c.idle = false;
      c.deadline_s = now_s_ + to_header_;
    }

    if (WM_UNLIKELY(!(cqe->flags & IORING_CQE_F_BUFFER))) {
      begin_close(idx);
      return;
    }
    const uint32_t bid0 = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    const size_t total = static_cast<size_t>(cqe->res);
    // Kernel-supplied values, checked before use: an id or length past the
    // pool would hand out someone else's memory.
    if (WM_UNLIKELY(bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize)) {
      begin_close(idx);
      return;
    }

    // A connection already condemned (close_after_send) reads nothing
    // more; its buffers still go back to the pool.
    if (WM_UNLIKELY(c.close_after_send)) {
      replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
      return;
    }

    // Walk the bundle: consecutive ids from bid0, every buffer full
    // except the last (dense-fill contract, io_uring_prep_recv(3)).
    std::string& sink = c.sending ? c.next : c.out;
    bool closing = false;
    size_t left = total;
    uint32_t bid = bid0;
    // The plan is offered on the LAST feed of the bundle alone, and
    // only when nothing is in flight (an in-flight sendmsg owns the
    // iovec arrays, and a plan against `next` would resolve against
    // the wrong string). Earlier segments park; the last one's flush
    // delivers everything parked by the whole bundle - so nothing is
    // lost to the split, it only rides one call later.
    typename App::Plan req;
    req.byte_cap = c.round_cap;
    while (left > 0) {
      const size_t n = left < kBufSize ? left : kBufSize;
      size_t off = 0;
      if (WM_UNLIKELY(__builtin_mul_overflow(static_cast<size_t>(bid),
                                             static_cast<size_t>(kBufSize), &off))) {
        begin_close(idx);
        return;
      }
      const bool last = left <= kBufSize;
      typename App::Plan* plan = (last && !c.sending) ? &req : nullptr;
      if (!closing) closing = !app_.feed(c.app, pool_ + off, n, sink, plan);
      left -= n;
      bid = (bid + 1) & (kBufCount - 1);
      replenish_++;
    }

    if (!c.sending) {
      if (req.nseg != 0) {
        take_plan(c, req);
        arm_send(idx);
      } else if (!c.out.empty()) {
        arm_send(idx);
      }
    }
    if (WM_UNLIKELY(closing)) {
      // Everything queued still drains; on_send finishes the close.
      if (c.sending) c.close_after_send = true;
      else begin_close(idx);
      return;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
  }

  void on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    c.sending = false;

    if (WM_UNLIKELY(cqe->res < 0)) {
      begin_close(idx);
      return;
    }
    const size_t took = static_cast<size_t>(cqe->res);
    // What was offered: the plan's total when there is one, `out`
    // alone otherwise.
    const size_t offered = c.niov != 0 ? c.plan_len : c.out.size();
    size_t new_sent = 0;
    // The kernel cannot have taken more than it was offered, and the sum
    // must not wrap - both are one check each, before anything uses them.
    if (WM_UNLIKELY(took > offered - c.sent ||
                    __builtin_add_overflow(c.sent, took, &new_sent))) {
      begin_close(idx);
      return;
    }
    c.sent = new_sent;
    // Progress on the wire: the send clock counts BETWEEN progresses
    // (nginx's send_timeout semantics), so it restarts here.
    c.deadline_s = now_s_ + to_send_;
    if (c.sent < offered) {
      arm_send(idx);  // partial: the rebuilt iovecs skip what already went
      return;
    }
    c.out.clear();
    c.sent = 0;
    c.niov = 0;  // the plan is spent; its pointers are nobody's business now
    c.plan_len = 0;
    // next drains BEFORE a pending close: an error response queued behind
    // an in-flight send must still reach the wire (RFC 9112 §9.6).
    if (!c.next.empty()) {
      c.out.swap(c.next);
      arm_send(idx);
      return;
    }
    if (app_.pending(c.app)) {
      // Work is owed: measure before building the next round, so the
      // round fits what the socket can take (Plan::byte_cap's story).
      // A connection owing nothing skips the beat entirely - hello
      // never pays it.
      arm_meminfo(idx);
      return;
    }
    continue_conn(idx);
  }

  // Ask the socket how much room it has, through the ring. The CQE
  // (kMeminfo) computes the round bound and THEN continues the
  // connection - the beat between send and next round that gives the
  // buffer a moment to drain and the answer a moment to land. One
  // extra SQE+CQE per pending round, riding the same submit.
  void arm_meminfo(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_GETSOCKOPT, static_cast<int>(idx), SOL_SOCKET,
                           SO_MEMINFO, c.mi, sizeof(c.mi));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kMeminfo, c.gen, idx));
  }

  // The peer's address, at accept, through the ring - the cmd has no
  // liburing helper yet, so the sqe is spelled by hand against
  // cmd_net.c's contract: addr = the sockaddr buffer, optval (union
  // addr3) = the length's in/out pointer, optlen = 1 for the PEER
  // form; ioprio/len/rw_flags must be zero (prep_rw zeroes them).
  void arm_peer(uint32_t idx) {
    Conn& c = conns_[idx];
    c.peer_slen = static_cast<int>(sizeof(c.peer_ss));
    struct io_uring_sqe* s = sqe();
    io_uring_prep_rw(IORING_OP_URING_CMD, s, static_cast<int>(idx), nullptr, 0, 0);
    s->cmd_op = SOCKET_URING_OP_GETSOCKNAME;
    s->addr = reinterpret_cast<uint64_t>(&c.peer_ss);
    s->optval = reinterpret_cast<uint64_t>(&c.peer_slen);
    s->optlen = 1;  // getPEERname
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kPeer, c.gen, idx));
  }
  void on_peer(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      // %h stays "-" for this connection; say why ONCE, not per accept
      // (an older kernel without the cmd would otherwise spam).
      static bool warned = false;
      if (!warned) {
        warned = true;
        std::fprintf(stderr, "webmachine: peer address unavailable (%s); %%h logs '-'\n",
                     std::strerror(-cqe->res));
      }
      return;
    }
    if (c.peer_slen > 0 && static_cast<size_t>(c.peer_slen) <= sizeof(c.peer_ss)) {
      c.app.peer = &c.peer_ss;
      c.app.peer_len = static_cast<uint8_t>(
          c.peer_slen > 255 ? 255 : c.peer_slen);
    }
  }

  void on_meminfo(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    size_t cap = Conn::kRoundFloor;
    if (WM_LIKELY(cqe->res >= 0)) {
      // TCP admits against wmem_queued, datagram-style sockets (unix
      // included) against wmem_alloc - the larger of the two is the
      // honest "used" on either family.
      const uint32_t used = c.mi[SK_MEMINFO_WMEM_QUEUED] > c.mi[SK_MEMINFO_WMEM_ALLOC]
                                ? c.mi[SK_MEMINFO_WMEM_QUEUED]
                                : c.mi[SK_MEMINFO_WMEM_ALLOC];
      const uint32_t buf = c.mi[SK_MEMINFO_SNDBUF];
      const size_t free_b = buf > used ? buf - used : 0;
      // Below the floor, send the floor anyway: the socket is full and
      // the ring's own poll is the right waiter - a shorter round
      // would only add beats to the same wait.
      if (free_b > cap) cap = free_b;
    }
    c.round_cap = cap;
    // A recv processed between the send's CQE and this one may have
    // armed a new send already - `out` is then the KERNEL's, and
    // continuing here would arm it a second time (measured as h2
    // frame corruption: duplicated bytes, 30 req/s of retries). The
    // cap is stored either way; the in-flight send's own completion
    // is the continuation.
    if (c.sending) return;
    continue_conn(idx);
  }

  // RESOLVE a plan into the connection's iovecs. A sink segment could
  // not carry a pointer while the plan was built - `out` was still
  // being appended to and every append may move it - so it carried an
  // offset, and this is the first moment the address is final. A plan
  // that names any sink range describes the round's sink COMPLETELY;
  // one of pure pointers (h1's transfer out of more()) leaves the sink
  // to be sent ahead of it - the prepend shifts the array by one, and
  // Conn::kIov reserves the slot.
  void take_plan(Conn& c, const typename App::Plan& req) {
    if (!c.iov) {
      c.iov = std::make_unique<struct iovec[]>(Conn::kIov);
      c.msg_iov = std::make_unique<struct iovec[]>(Conn::kIov);
    }
    c.niov = 0;
    c.plan_len = 0;
    bool sink_covered = false;
    for (unsigned i = 0; i < req.nseg; i++) {
      const typename App::Plan::Seg& sg = req.seg[i];
      if (sg.base != nullptr) {
        c.iov[c.niov].iov_base = const_cast<char*>(sg.base);
      } else {
        c.iov[c.niov].iov_base = c.out.data() + sg.off;
        sink_covered = true;
      }
      c.iov[c.niov].iov_len = sg.len;
      c.plan_len += sg.len;
      c.niov++;
    }
    if (!sink_covered && !c.out.empty()) {
      for (unsigned i = c.niov; i > 0; i--) c.iov[i] = c.iov[i - 1];
      c.iov[0].iov_base = c.out.data();
      c.iov[0].iov_len = c.out.size();
      c.plan_len += c.out.size();
      c.niov++;
    }
    c.sent = 0;
  }

  // The delivery continuation (#168): a fully drained sink is the one
  // signal every protocol produces. Backlog first - bytes queued in
  // `out` while a chain flew belong to EARLIER wire order than any new
  // round. Then the App speaks: bytes into `out`, or a PLAN - pointers
  // to bytes that already exist, which leave with the sink in one
  // sendmsg. Runs BEFORE a pending close is honored: a closing
  // response still delivers its source to the end.
  void continue_conn(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.out.empty()) {
      arm_send(idx);
      return;
    }
    // Default-init, NOT value-init: Plan's array is deliberately left
    // indeterminate (only [0, nseg) is ever read), because this runs
    // after EVERY drained send - hello pays it as often as a transfer.
    typename App::Plan req;
    req.byte_cap = c.round_cap;
    if (!app_.more(c.app, c.out, req)) c.close_after_send = true;
    if (req.nseg != 0) {
      take_plan(c, req);
      arm_send(idx);
      return;
    }
    if (!c.out.empty()) {
      arm_send(idx);
      return;
    }
    if (c.close_after_send) {
      c.close_after_send = false;
      begin_close(idx);
      return;
    }
    // Nothing owed, nothing in flight: the connection is BETWEEN
    // requests, and the idle clock owns it until the next first byte.
    c.idle = true;
    c.deadline_s = now_s_ + to_idle_;
  }
  void handle(struct io_uring_cqe* cqe) {
    const uint64_t ud = io_uring_cqe_get_data64(cqe);
    const uint8_t kind = static_cast<uint8_t>(ud >> 56);
    const uint16_t gen = static_cast<uint16_t>(ud >> 32);
    const uint32_t idx = static_cast<uint32_t>(ud);
    switch (kind) {
      case detail::kAccept: on_accept(idx, cqe); break;
      case detail::kRecv: on_recv(idx, gen, cqe); break;
      case detail::kSend: on_send(idx, gen, cqe); break;
      case detail::kMeminfo: on_meminfo(idx, gen, cqe); break;
      case detail::kLog: on_log(cqe); break;
      case detail::kPeer: on_peer(idx, gen, cqe); break;
      case detail::kClose:
        if (WM_UNLIKELY(cqe->res == -ECANCELED)) {
          // The linked shutdown failed (peer reset first); the close is
          // still owed or the direct slot leaks.
          struct io_uring_sqe* s = sqe();
          io_uring_prep_close_direct(s, idx);
          io_uring_sqe_set_data64(s, detail::tag(detail::kClose, gen, idx));
        }
        break;
      case detail::kShutdown: break;  // best effort; the linked close is the contract
      case detail::kStop: stop_ = true; break;
      default: break;
    }
  }

  // deadline: CLOCK_MONOTONIC_COARSE nanoseconds, or null for "no
  // bound". Everything the two callers share lives here; the ONLY
  // difference is the wait and where the batch may stop.
  bool step(const int64_t* deadline, bool bounded) {
    if (replenish_ != 0) {
      io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
      replenish_ = 0;
    }
    flush_log();
    if (bounded) {
      // The rest of the budget is what the WAIT may take. Already
      // spent: submit and take whatever is there, waiting for nothing.
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      const int64_t left =
          *deadline - (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec);
      struct io_uring_cqe* first = nullptr;
      if (left <= 0) {
        io_uring_submit(&ring_);
      } else {
        struct __kernel_timespec ts {left / 1000000000, left % 1000000000};
        // -ETIME is the budget doing its job, not a failure.
        io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
      }
    } else {
      // Bounded to a second even without a budget: the timeout clocks
      // (#180) need a wake when NOTHING completes - an idle server
      // wakes once a second, which is the whole cost of having
      // deadlines at all. -ETIME is the clock, not a failure.
      struct __kernel_timespec ts {1, 0};
      struct io_uring_cqe* first = nullptr;
      io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
    }
    {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      now_s_ = static_cast<int64_t>(now.tv_sec);
    }
    // Once per wake, never per request; the Ring does not know or care
    // what the App keeps fresh.
    app_.on_tick();
    bool worked = false;
    struct io_uring_cqe* cqe = nullptr;
    while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
      handle(cqe);
      io_uring_cqe_seen(&ring_, cqe);
      worked = true;
      if (bounded) {
        // Between completions, never inside one: a half-handled CQE
        // has no resumable state. What is left stays in the CQ - the
        // advance above only ever released what was HANDLED, so the
        // next tick reads it as if nothing had happened.
        struct timespec now {};
        ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        if (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec >= *deadline) break;
      }
    }
    if (!rearm_.empty()) {
      for (uint32_t idx : rearm_) {
        Conn& c = conns_[idx];
        // A condemned connection gets no new read; its close is in flight.
        if (c.live && !c.close_after_send) arm_recv(idx);
      }
      rearm_.clear();
    }
    // The reaper (#180): once per second, one compare per live
    // connection - at the derived max that is thousands of compares a
    // second, which is noise, and it is the cost #138 said a slow
    // connection may impose on the fast ones: a bounded, counted one.
    // AFTER the batch, so work that just happened has moved its
    // deadline; a connection mid-close is already spoken for.
    if (now_s_ != last_reap_s_) {
      last_reap_s_ = now_s_;
      for (uint32_t i = 0; i < max_conns_; i++) {
        Conn& c = conns_[i];
        if (!c.live) continue;
        // A timed source (#102) is asked here, and the idle clock is
        // not what owns it - silence is what an event stream mostly
        // is. While a send is in flight it is left alone: the send
        // deadline owns it then, and a peer that stopped reading is
        // still a peer that gets reaped.
        if (!c.sending && app_.timed(c.app)) {
          c.deadline_s = now_s_ + to_idle_;
          continue_conn(i);
          continue;
        }
        if (c.deadline_s >= now_s_) continue;
        if (c.sending) {
          // The stuck-send case: the SQE is parked on a peer that
          // reads nothing, so waiting for its CQE waits forever.
          // shutdown breaks it - the send completes with an error and
          // on_send finishes the close. Once: the flag remembers.
          if (!c.close_after_send) {
            c.close_after_send = true;
            struct io_uring_sqe* s = sqe();
            io_uring_prep_shutdown(s, static_cast<int>(i), SHUT_RDWR);
            s->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, i));
          }
        } else {
          begin_close(i);
        }
      }
    }
    if (draining_ && !stop_) {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      const int64_t at = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
      if (live_ == 0 || at >= drain_deadline_) stop_ = true;
    }
    return worked;
  }

  App& app_;
  struct io_uring ring_ {};
  bool ring_up_ = false;
  bool stop_ = false;
  bool bundles_ = false;
  // Derived at init from the raised RLIMIT_NOFILE (#169); 0 only
  // before init. listener_base_ = max_conns_: the listeners sit behind
  // the connection slots.
  int log_fd_ = -1;
  unsigned sq_entries_ = 0;  // what the SQ finally settled at
  int backlog_ = 511;        // listen(2) backlog; cfg.backlog overrides (#166)
  // #180's clocks (seconds; RingConfig names the defaults) and the
  // coarse now they compare against, refreshed once per wake.
  int to_header_ = 60;
  int to_send_ = 60;
  int to_idle_ = 75;
  int64_t now_s_ = 0;
  int64_t last_reap_s_ = 0;
  uint32_t max_conns_ = 0;
  uint32_t listener_base_ = 0;
  bool unix_listener_[kMaxListeners] = {};
  // TCP listeners' REAL ports after the bind: the spec's own number,
  // or the kernel's pick when the spec said 0. What conf.url reads
  // back through app_mark_bound. 0 for unix listeners.
  int bound_port_[kMaxListeners] = {};
  std::vector<std::string> unix_paths_;  // owned copies: the destructor unlinks them
  uint32_t nlisteners_ = 0;
  bool listeners_closed_ = false;
  // The drain (#116 slice 5): set once, never cleared - a server that
  // began stopping does not start again.
  bool draining_ = false;
  int64_t drain_deadline_ = 0;
  uint32_t live_ = 0;  // accepted connections still being served
  char* pool_ = nullptr;   // kBufCount * kBufSize, mmap'd once
  struct io_uring_buf_ring* buf_ring_ = nullptr;
  // Buffers consumed this tick, handed back (advance-only: the ring
  // entries were written once and consumption strictly rotates) at the
  // top of the NEXT tick - a Read's bytes stay valid until then.
  unsigned replenish_ = 0;
  std::vector<Conn> conns_;
  // Connections whose multishot recv ended this tick and must be
  // re-armed after the batch (their prep would race the buffer advance).
  std::vector<uint32_t> rearm_;
};

}  // namespace webmachine

#endif
