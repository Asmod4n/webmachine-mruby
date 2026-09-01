// Design decisions live in .DESIGN.md, filed under what each comment names.
#ifndef WEBMACHINE_HPP
#define WEBMACHINE_HPP

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ktls.h>
#include <liburing.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
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
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// openat2(2) IS the docroot confinement response.file rests on, so a
// toolchain whose kernel headers predate it must not silently lose the
// hardening - same shape as the SO_MEMINFO fallback further down, and the
// kernel's own fixed ABI values read off linux/openat2.h, never guessed.
// RESOLVE_BENEATH alone blocks ".."/absolute escapes but NOT a symlink INSIDE
// the docroot pointing out; NO_SYMLINKS closes that, NO_MAGICLINKS closes the
// /proc-style ones. All three, always - each covers what the others do not.
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#else
struct open_how {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x08
#endif

// picohttpparser's field pair; the framers include the header itself.
struct phr_header;

namespace webmachine::flow {
// Alan Dean and Justin Sheehy's HTTP decision diagram; the letters are
// its node names. Each edge's clause is in kFlow's `clause` column.
enum class Node : uint8_t {
  kB13, kB12, kB11, kB10, kB9b, kB8, kB7, kB6, kB5, kB4, kB3,
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

// Also ours: WHO decides a node. RFC 9110 has no such split - it is the
// fold's, and it is what lets a kRequest node answer without the VM.
enum class Kind : uint8_t { kRequest, kResource, kConneg, kAction };

struct Target {
  Node node;
  uint16_t status;
};
// The graph as data: an edge that continues to a node.
constexpr Target to(Node n) { return {n, 0}; }
// The graph as data: an edge that halts with a status.
constexpr Target halt(uint16_t s) { return {Node::kCount, s}; }

// One row of the diagram. `callback` is webmachine-ruby's method name for
// this node, verbatim - that is the contract an app writes against.
// `clause` is the RFC 9110 section the edge implements, which is what a
// reader needs when the diagram and the specification are both open.
struct FlowNode {
  Node id;
  Kind kind;
  const char* callback;
  const char* clause;
  Target on_true;
  Target on_false;
};

inline constexpr FlowNode kFlow[] = {
    {Node::kB13, Kind::kResource, "service_available?", "RFC 9110 15.6.4 (503)",
     to(Node::kB12), halt(503)},
    {Node::kB12, Kind::kResource, "known_methods", "RFC 9110 15.6.2 (501); list x method",
     to(Node::kB11), halt(501)},
    {Node::kB11, Kind::kResource, "uri_too_long?", "RFC 9110 15.5.15 (414)",
     halt(414), to(Node::kB10)},
    {Node::kB10, Kind::kResource, "allowed_methods", "RFC 9110 15.5.6 (405) + 10.2.1 Allow",
     to(Node::kB9b), halt(405)},
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

// Proof: the table is indexed by its own ids.
constexpr bool ids_in_order() {
  for (size_t i = 0; i < kNodeCount; i++) {
    if (kFlow[i].id != static_cast<Node>(i)) return false;
  }
  return true;
}
static_assert(ids_in_order(), "kFlow order must match Node order");

constexpr bool target_names_a_node_or_a_status(const Target& t) {
  if (t.status == 0) return t.node < Node::kCount;
  return t.status >= 100 && t.status <= 599;
}
constexpr bool both_targets_of_every_node_name_one() {
  for (size_t i = 0; i < kNodeCount; i++) {
    if (!target_names_a_node_or_a_status(kFlow[i].on_true) ||
        !target_names_a_node_or_a_status(kFlow[i].on_false)) {
      return false;
    }
  }
  return true;
}
static_assert(both_targets_of_every_node_name_one(), "every edge continues or halts");

// Proof: no cycle, and so every path from here halts.
//
// A depth-first walk that colours each node - kUnseen, kOnThePath,
// kFinished - where a node met again while it is still ON the path is a
// back edge, which is what a cycle is. Each node is entered once and
// left once, so this walks the GRAPH; the earlier form walked every
// PATH through it, which is exponential in the number of branches and
// crashed gcc 16's constexpr evaluator outright.
enum : uint8_t { kUnseen = 0, kOnThePath = 1, kFinished = 2 };
constexpr bool no_cycle_from(Node n, uint8_t (&colour)[kNodeCount]) {
  const size_t i = static_cast<size_t>(n);
  if (colour[i] == kOnThePath) return false;
  if (colour[i] == kFinished) return true;
  colour[i] = kOnThePath;
  const FlowNode& f = kFlow[i];
  if (f.on_true.status == 0 && !no_cycle_from(f.on_true.node, colour)) return false;
  if (f.on_false.status == 0 && !no_cycle_from(f.on_false.node, colour)) return false;
  colour[i] = kFinished;
  return true;
}
constexpr bool the_flow_is_acyclic() {
  uint8_t colour[kNodeCount] = {};
  return no_cycle_from(Node::kB13, colour);
}
static_assert(the_flow_is_acyclic(), "the flow is acyclic from B13");

// Proof: reachability, both branches from every node.
constexpr void mark(Node n, bool (&seen)[kNodeCount]) {
  const size_t i = static_cast<size_t>(n);
  if (seen[i]) return;
  seen[i] = true;
  const FlowNode& f = kFlow[i];
  if (f.on_true.status == 0) mark(f.on_true.node, seen);
  if (f.on_false.status == 0) mark(f.on_false.node, seen);
}
// Proof: no dead entry - a dead node would be an untested lie.
constexpr bool all_reachable() {
  bool seen[kNodeCount] = {};
  mark(Node::kB13, seen);
  for (bool s : seen) {
    if (!s) return false;
  }
  return true;
}
static_assert(all_reachable(), "every node is reachable from B13");
}

namespace webmachine::flow {
// RFC 9110 9.3: the methods this server names. kOther is not a method -
// it is "some token we did not recognise", which b12 turns into 501.
enum class Method : uint8_t { kGet, kHead, kPost, kPut, kDelete, kOptions, kOther };

// RFC 9110: everything a kRequest node needs, decided from the parsed
// request alone. Every field is a FIELD OF THE SPECIFICATION and now
// spells it out - has_if_unmodified_since used to sit next to ius_valid,
// the same header abbreviated in one line and not in the next.
//   has_accept*                 RFC 9110 12.5.1-12.5.4
//   has_if_match, *_star        RFC 9110 13.1.1
//   has_if_unmodified_since     RFC 9110 13.1.4
//   has_if_none_match, *_star   RFC 9110 13.1.2
//   has_if_modified_since       RFC 9110 13.1.3
//   *_valid                     RFC 9110 5.6.7: it parsed as an HTTP-date
//   response_has_*              RFC 9110 10.2.2 / 6.4, set by the run
//   plain, no_track             NO RFC: the access log's privacy bits,
//                               from DNT and Sec-GPC, neither of which
//                               any RFC defines
struct ReqFacts {
  Method method = Method::kGet;
  bool has_accept = false;
  bool has_accept_language = false;
  bool has_accept_charset = false;
  bool has_accept_encoding = false;
  bool has_if_match = false;
  bool if_match_star = false;
  bool has_if_unmodified_since = false;
  bool if_unmodified_since_valid = false;
  bool has_if_none_match = false;
  bool if_none_match_star = false;
  bool has_if_modified_since = false;
  bool if_modified_since_valid = false;
  bool if_modified_since_future = false;
  // RFC 9110 12.5.1: whether this request's Accept names a media type
  // the bound resource offers. True by default so a request without an
  // Accept header negotiates nothing, exactly as c3 sends it.
  bool accept_ok = true;
  bool response_has_location = false;
  bool response_has_body = true;
  bool plain = true;
  bool no_track = false;

  // RFC 9110 12.5: did the request name any of the four negotiation fields?
  // Derived, never stored - a second copy is a second thing to keep true.
  constexpr bool names_a_conneg_field() const {
    return has_accept || has_accept_language || has_accept_charset || has_accept_encoding;
  }
  // RFC 9110 13: the same question for the four conditional fields.
  constexpr bool names_a_conditional_field() const {
    return has_if_match || has_if_unmodified_since || has_if_none_match ||
           has_if_modified_since;
  }
};

// NO RFC: the fold's own result. What a resource answered at SETUP, once,
// for every node whose answer cannot change per request.
struct KonstAnswers {
  bool ans[kNodeCount] = {};
};

// RFC 9110: the kRequest nodes - decided from the parsed request alone,
// never from the VM.
constexpr bool eval_request(Node id, const ReqFacts& r) {
  switch (id) {
    case Node::kB3: return r.method == Method::kOptions;
    case Node::kC3: return r.has_accept;
    case Node::kC4: return r.accept_ok;
    case Node::kD4: return r.has_accept_language;
    case Node::kE5: return r.has_accept_charset;
    case Node::kF6: return r.has_accept_encoding;
    case Node::kG8: return r.has_if_match;
    case Node::kG9: return r.if_match_star;
    case Node::kH7: return r.has_if_match && r.if_match_star;
    case Node::kH10: return r.has_if_unmodified_since;
    case Node::kH11: return r.if_unmodified_since_valid;
    case Node::kI7: return r.method == Method::kPut;
    case Node::kI12: return r.has_if_none_match;
    case Node::kI13: return r.if_none_match_star;
    case Node::kJ18: return r.method == Method::kGet || r.method == Method::kHead;
    case Node::kL7: return r.method == Method::kPost;
    case Node::kL13: return r.has_if_modified_since;
    case Node::kL14: return r.if_modified_since_valid;
    case Node::kL15: return r.if_modified_since_future;
    case Node::kM5: return r.method == Method::kPost;
    case Node::kM16: return r.method == Method::kDelete;
    case Node::kN16: return r.method == Method::kPost;
    case Node::kO16: return r.method == Method::kPut;
    case Node::kO20: return r.response_has_body;
    case Node::kP11: return r.response_has_location;
    default: return false;
  }
}

// RFC 9110: the graph, run with this request's facts and a resource's
// konst answers. Zero VM entries.
// RFC 9110 12.5: c4/d5/e6/f7 are reachable only through the has_* node above
// each of them, so a request naming none of the four fields walks c3 -> d4 ->
// e5 -> f6 -> g7 and can say nothing on the way. The absence IS the answer.
inline constexpr Node kAfterConneg = Node::kG7;
// RFC 9110 13: the same shape - g9/g11, h11/h12, i13/k13/j18 and l14/l15/l17
// all hang off their own has_*, so a request naming none of the four walks
// g8 -> h10 -> i12 -> l13 -> m16.
inline constexpr Node kAfterConditional = Node::kM16;

constexpr uint16_t walk(const ReqFacts& req, const KonstAnswers& k) {
  Node n = Node::kB13;
  for (;;) {
    if (n == Node::kC3 && !req.names_a_conneg_field()) n = kAfterConneg;
    else if (n == Node::kG8 && !req.names_a_conditional_field()) n = kAfterConditional;
    const FlowNode& f = kFlow[static_cast<size_t>(n)];
    // c4 reads the request as surely as any kRequest node does - it is the
    // client's Accept against this resource's types, and no fold can bake
    // that. The other kConneg nodes (d5/e6/f7) stay konst: languages and
    // charsets are named refusal in this tree, so their answer never moves.
    const bool ans = (f.kind == Kind::kRequest || n == Node::kC4)
                         ? eval_request(n, req)
                         : k.ans[static_cast<size_t>(n)];
    const Target& t = ans ? f.on_true : f.on_false;
    if (t.status != 0) return t.status;
    n = t.node;
  }
}

struct Shortcut {
  uint16_t status = 0;
  bool always = false;
};

// c4 counts as one, for the reason walk() gives above.
constexpr bool reaches_a_node_that_reads_the_request(Node n, const KonstAnswers& k, bool* seen) {
  if (seen[static_cast<size_t>(n)]) return false;
  seen[static_cast<size_t>(n)] = true;
  const FlowNode& f = kFlow[static_cast<size_t>(n)];
  if (f.kind == Kind::kRequest || n == Node::kC4) return true;
  const Target& t = k.ans[static_cast<size_t>(n)] ? f.on_true : f.on_false;
  if (t.status != 0) return false;
  return reaches_a_node_that_reads_the_request(t.node, k, seen);
}

// The two skips above are claims about the graph, so the graph is asked.
// From `from`, with the block's fields absent, follow the edges the way walk
// does and report where it comes out. kNodeCount is the give-up bound: a
// halt or a wrong exit both fail the assert below.
constexpr Node lands_on(Node from, const ReqFacts& req, const KonstAnswers& k) {
  Node n = from;
  for (size_t step = 0; step < kNodeCount; step++) {
    const FlowNode& f = kFlow[static_cast<size_t>(n)];
    const bool ans = (f.kind == Kind::kRequest || n == Node::kC4)
                         ? eval_request(n, req)
                         : k.ans[static_cast<size_t>(n)];
    const Target& t = ans ? f.on_true : f.on_false;
    if (t.status != 0) return Node::kB13;  // halted: not an exit
    n = t.node;
    if (n == kAfterConneg || n == kAfterConditional) return n;
  }
  return Node::kB13;
}

// Neither block's chain reads konst - c4/d5/e6/f7 and g9/g11/h11/h12/i13/
// k13/l14/l15/l17 all hang off a has_* that is false here - so both konst
// extremes have to give the same exit, for every method.
constexpr bool block_skips_are_the_graphs(Method m) {
  ReqFacts absent;
  absent.method = m;
  KonstAnswers all_false{};
  KonstAnswers all_true{};
  for (size_t i = 0; i < kNodeCount; i++) all_true.ans[i] = true;
  return lands_on(Node::kC3, absent, all_false) == kAfterConneg &&
         lands_on(Node::kC3, absent, all_true) == kAfterConneg &&
         lands_on(Node::kG8, absent, all_false) == kAfterConditional &&
         lands_on(Node::kG8, absent, all_true) == kAfterConditional;
}
static_assert(block_skips_are_the_graphs(Method::kGet));
static_assert(block_skips_are_the_graphs(Method::kHead));
static_assert(block_skips_are_the_graphs(Method::kPost));
static_assert(block_skips_are_the_graphs(Method::kPut));
static_assert(block_skips_are_the_graphs(Method::kDelete));
static_assert(block_skips_are_the_graphs(Method::kOptions));
static_assert(block_skips_are_the_graphs(Method::kOther));

// RFC 9110: what the graph would say when it has nothing to decide -
// from the SAME walk, run once with every header fact false.
constexpr Shortcut shortcut_for(Method m, const KonstAnswers& k) {
  Shortcut s;
  ReqFacts plain_facts;
  plain_facts.method = m;
  s.status = walk(plain_facts, k);
  bool seen[kNodeCount] = {};
  s.always = !reaches_a_node_that_reads_the_request(Node::kB13, k, seen);
  return s;
}

// RFC 9110: the one entry point the request path calls. Two integer tests
// where the graph could not have said anything else.
constexpr uint16_t answer(const ReqFacts& req, const KonstAnswers& k, const Shortcut& s) {
  if (s.always || req.plain) return s.status;
  return walk(req, k);
}

namespace detail {
// The whole remaining walk from N, unrolled: K's answers are constants,
// so only kRequest nodes survive as branches.
template <KonstAnswers K, Node N>
constexpr uint16_t status_reached_from(const ReqFacts& req) {
  constexpr FlowNode f = kFlow[static_cast<size_t>(N)];
  if constexpr (f.kind != Kind::kRequest) {
    constexpr Target t = K.ans[static_cast<size_t>(N)] ? f.on_true : f.on_false;
    if constexpr (t.status != 0) return t.status;
    else return status_reached_from<K, t.node>(req);
  } else {
    if (eval_request(N, req)) {
      if constexpr (f.on_true.status != 0) return f.on_true.status;
      else return status_reached_from<K, f.on_true.node>(req);
    } else {
      if constexpr (f.on_false.status != 0) return f.on_false.status;
      else return status_reached_from<K, f.on_false.node>(req);
    }
  }
}
}

template <KonstAnswers K>
constexpr uint16_t walk_compiled(const ReqFacts& req) {
  return detail::status_reached_from<K, Node::kB13>(req);
}

// RFC 9110: webmachine-ruby's Resource defaults, folded per method.
constexpr KonstAnswers answers_of_an_unoverridden_resource(Method m) {
  KonstAnswers k{};
  k.ans[static_cast<size_t>(Node::kB13)] = true;
  k.ans[static_cast<size_t>(Node::kB12)] = m != Method::kOther;
  k.ans[static_cast<size_t>(Node::kB11)] = false;
  k.ans[static_cast<size_t>(Node::kB10)] = m == Method::kGet || m == Method::kHead;
  k.ans[static_cast<size_t>(Node::kB9b)] = false;
  k.ans[static_cast<size_t>(Node::kB8)] = true;
  k.ans[static_cast<size_t>(Node::kB7)] = false;
  k.ans[static_cast<size_t>(Node::kB6)] = true;
  k.ans[static_cast<size_t>(Node::kB5)] = true;
  k.ans[static_cast<size_t>(Node::kB4)] = true;
  k.ans[static_cast<size_t>(Node::kG7)] = true;
  k.ans[static_cast<size_t>(Node::kC4)] = true;
  k.ans[static_cast<size_t>(Node::kD5)] = true;
  k.ans[static_cast<size_t>(Node::kE6)] = true;
  k.ans[static_cast<size_t>(Node::kF7)] = true;
  k.ans[static_cast<size_t>(Node::kL17)] = true;
  k.ans[static_cast<size_t>(Node::kM20b)] = true;
  k.ans[static_cast<size_t>(Node::kO18)] = true;
  k.ans[static_cast<size_t>(Node::kO18b)] = false;
  return k;
}

struct KonstSet {
  KonstAnswers per_method[7];
  Shortcut shortcut[7];
  std::string allow = "GET, HEAD";
  std::string body = "OK";
  std::string content_type;
  // RFC 9110: a resource that overrides nothing - webmachine-ruby's defaults.
  KonstSet() {
    for (uint8_t m = 0; m < 7; m++) per_method[m] = answers_of_an_unoverridden_resource(static_cast<Method>(m));
    resolve_shortcuts();
  }
  // RFC 9110: the shortcuts are derived from per_method; whoever changes
  // one must call this.
  void resolve_shortcuts() {
    for (uint8_t m = 0; m < 7; m++) {
      shortcut[m] = shortcut_for(static_cast<Method>(m), per_method[m]);
    }
  }
};

namespace proof {
constexpr ReqFacts get_plain{};
static_assert(walk(get_plain, answers_of_an_unoverridden_resource(Method::kGet)) == 200,
              "plain GET on the default resource is 200");
constexpr ReqFacts get_negotiated{.has_accept = true,
                                  .has_accept_language = true,
                                  .has_accept_charset = true,
                                  .has_accept_encoding = true};
static_assert(walk(get_negotiated, answers_of_an_unoverridden_resource(Method::kGet)) == 200,
              "a browser GET negotiates through C4/D5/E6/F7 to 200");
constexpr ReqFacts get_unacceptable{.has_accept = true, .accept_ok = false};
static_assert(walk(get_unacceptable, answers_of_an_unoverridden_resource(Method::kGet)) == 406,
              "an Accept that names no offered type is 406 at C4, konst tier included");
constexpr ReqFacts unknown{.method = Method::kOther};
static_assert(walk(unknown, answers_of_an_unoverridden_resource(Method::kOther)) == 501,
              "an unknown method dies at B12 with 501");
constexpr ReqFacts options{.method = Method::kOptions};
static_assert(walk(options, answers_of_an_unoverridden_resource(Method::kOptions)) == 405,
              "OPTIONS not in default allowed_methods dies at B10 like anything else");
constexpr KonstAnswers options_allowed = [] {
  KonstAnswers k = answers_of_an_unoverridden_resource(Method::kOptions);
  k.ans[static_cast<size_t>(Node::kB10)] = true;
  return k;
}();
static_assert(walk(options, options_allowed) == 200,
              "OPTIONS answers 200 from options() once allowed (B3)");
constexpr ReqFacts del{.method = Method::kDelete};
static_assert(walk(del, answers_of_an_unoverridden_resource(Method::kDelete)) == 405,
              "default allowed_methods is GET/HEAD: DELETE is 405 at B10");
constexpr ReqFacts if_none_match_star{.has_if_none_match = true, .if_none_match_star = true};
static_assert(walk(if_none_match_star, answers_of_an_unoverridden_resource(Method::kGet)) == 304,
              "GET with If-None-Match: * on an existing resource is 304");
constexpr ReqFacts im_star_missing{.has_if_match = true, .if_match_star = true};
constexpr KonstAnswers missing = [] {
  KonstAnswers k = answers_of_an_unoverridden_resource(Method::kGet);
  k.ans[static_cast<size_t>(Node::kG7)] = false;
  return k;
}();
static_assert(walk(im_star_missing, missing) == 412,
              "If-Match: * against a missing resource is 412 (H7)");
static_assert(walk(get_plain, missing) == 404,
              "GET on a never-existed resource is 404 (L7)");
static_assert(walk_compiled<answers_of_an_unoverridden_resource(Method::kGet)>(get_plain) == 200);
static_assert(walk_compiled<answers_of_an_unoverridden_resource(Method::kDelete)>(del) == 405);
static_assert(walk_compiled<answers_of_an_unoverridden_resource(Method::kGet)>(if_none_match_star) == 304);
static_assert(walk_compiled<missing>(im_star_missing) == 412);
static_assert(walk_compiled<missing>(get_plain) == 404);
}
}

namespace webmachine {
inline constexpr size_t kMaxRouteBindings = 16;

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

  // route.add: begin a route. abandon() rolls it back whole.
  void open() {
    pending_first_ = toks_.size();
    pending_blob_ = blob_.size();
    pending_binds_ = 0;
    pending_splat_ = false;
  }
  // RFC 9110 4.2.1: a String token is a literal segment.
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
  // RFC 9110 4.2.1: a Symbol token binds one segment; its id rides along
  // so the request object can NAME what a span captured.
  bool binding(uint32_t sym) {
    if (pending_binds_ >= kMaxRouteBindings) return false;
    pending_binds_++;
    toks_.push_back(RouteToken{kBinding, sym, 0});
    return true;
  }

  // The name of a route's i-th binding, in the order match() captured them.
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
  // RFC 9110 4.2.1: :* is the tail, and by construction the last token.
  void splat() {
    pending_splat_ = true;
    toks_.push_back(RouteToken{kSplat, 0, 0});
  }
  // Is the route under construction already splatted?
  bool pending_splat() const { return pending_splat_; }
  // route.add: the route stands.
  void commit() {
    Route r;
    r.first = static_cast<uint32_t>(pending_first_);
    r.count = static_cast<uint32_t>(toks_.size() - pending_first_);
    routes_.push_back(r);
  }
  // route.add: a route that failed validation leaves NOTHING registered.
  void abandon() {
    toks_.resize(pending_first_);
    blob_.resize(pending_blob_);
  }

  // How many routes this table holds.
  size_t size() const { return routes_.size(); }
  // Has this app any route of this kind at all?
  bool empty() const { return routes_.empty(); }

  // RFC 9110 4.2.1: the FIRST route that matches wins (registration order).
  // -1 is a miss, and a miss answers 404 before B13.
  int match(const char* path, size_t len, RouteSpans& out) const {
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
        if (p < plen) p++;
      }
      if (!ok) continue;
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
    uint32_t off;
    uint32_t len;
  };
  struct Route {
    uint32_t first;
    uint32_t count;
  };
  std::string blob_;
  std::vector<RouteToken> toks_;
  std::vector<Route> routes_;
  size_t pending_first_ = 0;
  size_t pending_blob_ = 0;
  size_t pending_binds_ = 0;
  bool pending_splat_ = false;
};
}

namespace webmachine {
// NO RFC - and that is the finding worth writing down. The access log is
// the NCSA Combined Log Format: something httpd shipped and everyone
// copied, never specified, so no line here can be checked against a
// source. What the fields MEAN is specified (RFC 9110); how they are
// spelled onto a line is not. Logger is this server's own plumbing - the
// records are formatted here and drained by the ring to webmachine-logd.
struct Logger {
  bool enabled = false;
  std::string pending;       // formatted, not yet handed to the ring
  std::string flight;        // handed over; the kernel owns these bytes
  bool in_flight = false;
  int64_t unix_seconds = 0;  // the reactor's cached wall clock, per batch
};

// One response as one record. The format is ours (see Logger above); the
// fields are not:
//   status_code      RFC 9110 15
//   content_length   RFC 9110 8.6 - octets of content, headers excluded
//   method_token     RFC 9110 9.1
//   request_target   RFC 9112 3.2
//   referer          RFC 9110 10.1.3 - the RFC misspells it, so do we
//   user_agent       RFC 9110 10.1.5
//   peer             no RFC: the socket's address, already spelled
//   unix_seconds     no RFC: the clock
// The *_len fields are this record's framing, not content: their widths
// ARE the truncation caps, which is why log_access clamps to them.
struct LogRec {
  uint8_t version;
  uint8_t flags;
  uint16_t status_code;
  uint32_t content_length;
  int64_t unix_seconds;
  uint8_t method_token_len;
  uint8_t peer_len;
  uint16_t request_target_len;
  uint16_t referer_len;
  uint16_t user_agent_len;
};
inline constexpr uint8_t kLogRecVersion = 3;
inline constexpr uint8_t kLogH2 = 1;       // RFC 9113: the version token
inline constexpr uint8_t kLogNoTrack = 2;  // no RFC: operator's choice

// Combined Log Format: one response as one record. The five views and the
// four numbers travelled together through fourteen arguments before -
// see #std-first; this is what they are.
struct AccessLine {
  std::string_view peer;           // the socket's address, already spelled
  std::string_view method_token;   // RFC 9110 9.1
  std::string_view request_target; // RFC 9112 3.2
  std::string_view referer;        // RFC 9110 10.1.3 - the RFC misspells it
  std::string_view user_agent;     // RFC 9110 10.1.5
  size_t content_length = 0;       // RFC 9110 8.6 - content octets, no headers
  uint16_t status_code = 0;        // RFC 9110 15
  uint8_t flags = 0;
};

// Truncation caps are the wire fields' widths.
inline void log_access(Logger& lg, const AccessLine& line) {
  size_t peer_len = line.peer.size();
  size_t method_token_len = line.method_token.size();
  size_t request_target_len = line.request_target.size();
  size_t referer_len = line.referer.size();
  size_t user_agent_len = line.user_agent.size();
  const uint8_t flags = line.flags;
  const uint16_t status_code = line.status_code;
  const size_t content_length = line.content_length;
  const char* peer = line.peer.data();
  const char* method_token = line.method_token.data();
  const char* request_target = line.request_target.data();
  const char* referer = line.referer.data();
  const char* user_agent = line.user_agent.data();
  if (method_token_len > 255) method_token_len = 255;
  if (peer_len > 255) peer_len = 255;
  if (request_target_len > 65535) request_target_len = 65535;
  if (referer_len > 65535) referer_len = 65535;
  if (user_agent_len > 65535) user_agent_len = 65535;
  LogRec r;
  r.version = kLogRecVersion;
  r.flags = flags;
  r.status_code = status_code;
  r.content_length =
      content_length > 0xffffffffull ? 0xffffffffu : static_cast<uint32_t>(content_length);
  r.unix_seconds = lg.unix_seconds;
  r.method_token_len = static_cast<uint8_t>(method_token_len);
  r.peer_len = static_cast<uint8_t>(peer_len);
  r.request_target_len = static_cast<uint16_t>(request_target_len);
  r.referer_len = static_cast<uint16_t>(referer_len);
  r.user_agent_len = static_cast<uint16_t>(user_agent_len);
  lg.pending.append(reinterpret_cast<const char*>(&r), sizeof r);
  if (method_token_len != 0) lg.pending.append(method_token, method_token_len);
  if (peer_len != 0) lg.pending.append(peer, peer_len);
  if (request_target_len != 0) lg.pending.append(request_target, request_target_len);
  if (referer_len != 0) lg.pending.append(referer, referer_len);
  if (user_agent_len != 0) lg.pending.append(user_agent, user_agent_len);
}

// One raise as one record. Same finding as LogRec - no format specifies
// this - and here even the CONTENT mostly has no source: an exception
// class, a message and a backtrace are mruby's, not any RFC's.
//   status_code           RFC 9110 15, or 0 when the raise never reached
//                         an answer
//   request_target        RFC 9112 3.2
//   peer                  no RFC: the socket's address
//   exception_class,      no RFC: mruby. Note message_len is the
//   message, backtrace    EXCEPTION's message - LogRec's neighbouring
//                         field of the same shape is a METHOD's length,
//                         which is why neither is called mlen any more.
//   dynamic_len           no RFC: it is the LENGTH argument of the second
//                         io_uring_prep_send, so the daemon can read this
//                         fixed header first and then take exactly that
//                         many bytes.
struct ErrRec {
  uint8_t version;
  uint8_t flags;
  uint16_t status_code;
  int64_t unix_seconds;
  uint8_t peer_len;
  uint8_t exception_class_len;
  uint16_t request_target_len;
  uint16_t message_len;
  uint16_t backtrace_len;
  uint8_t method_len;
  uint8_t steering_len;
  // What the request carried, capped at kBodyKept - body_full_len is what
  // it really was, so a record says "50 MB, here are the first 4 KB"
  // rather than passing a truncation off as the whole of it.
  uint16_t body_len;
  uint32_t body_full_len;
  // #210: the fingerprint of what led here, as the page spells it. The
  // same 16 bytes in both, so the hash a user reads off a page is the
  // string that finds this record - no lookup table in between. app_build
  // is the build it happened in, so a hash from before a deploy is told
  // apart from one from the running code instead of being chased.
  char fingerprint[16];
  char app_build[16];
  uint32_t dynamic_len;
};
inline constexpr uint8_t kErrRecVersion = 2;
inline constexpr size_t kFingerprintLen = 16;
// How much of a request body one record keeps. The body is what an app
// was asked to do, so it is what says why a raise happened - and it is
// also whatever the app put there, which for a form login is a password.
// An error log is a file with secrets in it; give it the permissions and
// the retention that says so.
inline constexpr size_t kBodyKept = 4096;

// What THIS build of the app is: FNV-1a over the bytecode the server
// loaded, taken once at startup. Every fingerprint carries it, so a rake
// that changed anything gives every failure a new hash - a hash reported
// yesterday can never point at a line that has moved or a method that is
// gone. A build property, not a request's: it is the same for every
// answer this process gives.
inline uint64_t& app_build_hash() {
  static uint64_t h = 0;
  return h;
}

// FNV-1a, 64 bit (Fowler/Noll/Vo, offset basis and prime by the reference
// implementation). One raise's fingerprint is this over everything that
// led to it, fed piece by piece.
inline constexpr uint64_t kFnvBasis = 0xcbf29ce484222325ULL;
inline uint64_t fnv1a(uint64_t h, const void* p, size_t n) {
  const unsigned char* b = static_cast<const unsigned char*>(p);
  size_t i = 0;
  for (; i < n; i++) {
    h ^= b[i];
    h *= 0x100000001b3ULL;
  }
  return h;
}
// A length in front of every piece, so two pieces that meet cannot spell
// what a different pair would: "/a" + "bc" and "/ab" + "c" are two
// fingerprints, not one.
inline uint64_t fnv1a_piece(uint64_t h, const void* p, size_t n) {
  const uint32_t len = static_cast<uint32_t>(n);
  h = fnv1a(h, &len, sizeof len);
  return n != 0 ? fnv1a(h, p, n) : h;
}
// The 16 lowercase hex digits a page shows and a log carries.
inline void spell_fingerprint(char* out, uint64_t h) {
  static const char kHex[] = "0123456789abcdef";
  size_t i = 0;
  for (; i < kFingerprintLen; i++) out[i] = kHex[(h >> ((15 - i) * 4)) & 0xf];
}

// What ONE failure was: the request that led there, and the raise that
// ended it. Read, never written, by everything below - the fingerprint is
// this and nothing else, so a record and a page cannot disagree about
// what the hash was taken over.
struct ErrFacts {
  const void* peer = nullptr;
  size_t peer_len = 0;
  // The request, as far as it steered: the target the client asked for,
  // the method it asked with, and the fields the server reads because
  // they change the answer (spell_steering below). Referer and
  // User-Agent are not among them - they steer nothing.
  const char* request_target = nullptr;
  size_t request_target_len = 0;
  const char* method = nullptr;
  size_t method_len = 0;
  const char* steering = nullptr;
  size_t steering_len = 0;
  // The raise: what was thrown, what it said, and where from.
  const char* exception_class = nullptr;
  size_t exception_class_len = 0;
  const char* message = nullptr;
  size_t message_len = 0;
  const char* backtrace = nullptr;
  size_t backtrace_len = 0;
  // What the request carried. Without it a raise inside a handler says
  // where it happened and not what it was asked to do. body_full is what
  // arrived; log_error keeps kBodyKept of it and records the rest as a
  // number.
  const char* body = nullptr;
  size_t body_len = 0;
  size_t body_full = 0;
  uint16_t status_code = 0;
};

// The hash a user reads off the page and an operator greps the log for.
// Everything that led here goes in, each piece behind its own length; the
// message does not - the same fault at the same place under the same
// request is one failure, whatever the exception chose to say about it.
inline uint64_t fingerprint_of(const ErrFacts& f) {
  uint64_t h = app_build_hash();
  h = fnv1a_piece(h, f.method, f.method_len);
  h = fnv1a_piece(h, f.request_target, f.request_target_len);
  h = fnv1a_piece(h, f.steering, f.steering_len);
  h = fnv1a_piece(h, f.exception_class, f.exception_class_len);
  h = fnv1a_piece(h, f.backtrace, f.backtrace_len);
  h = fnv1a_piece(h, &f.status_code, sizeof f.status_code);
  return h;
}

// One raise as one record: a FIXED header whose last field is the size of
// the second send, then that many bytes - peer, class, target, message,
// backtrace, method, steering, in that order.
inline void log_error(Logger& lg, const ErrFacts& f) {
  // A 4xx is an answer, not a failure: the client asked for something it
  // may not have, and the server said so. Nothing raised, so there is
  // nothing to explain and no hash to hand out. Refused here, once, so no
  // call site has to remember it.
  if (f.status_code >= 400 && f.status_code < 500) return;
  const size_t peer_len = f.peer_len > 255 ? 255 : f.peer_len;
  const size_t class_len = f.exception_class_len > 255 ? 255 : f.exception_class_len;
  const size_t target_len = f.request_target_len > 65535 ? 65535 : f.request_target_len;
  const size_t message_len = f.message_len > 65535 ? 65535 : f.message_len;
  const size_t backtrace_len = f.backtrace_len > 65535 ? 65535 : f.backtrace_len;
  const size_t method_len = f.method_len > 255 ? 255 : f.method_len;
  const size_t steering_len = f.steering_len > 255 ? 255 : f.steering_len;
  const size_t body_len = f.body_len > kBodyKept ? kBodyKept : f.body_len;
  ErrRec r;
  r.version = kErrRecVersion;
  r.flags = 0;  // no RFC, and nothing sets it yet: reserved on the wire
  r.status_code = f.status_code;
  r.unix_seconds = lg.unix_seconds;
  r.peer_len = static_cast<uint8_t>(peer_len);
  r.exception_class_len = static_cast<uint8_t>(class_len);
  r.request_target_len = static_cast<uint16_t>(target_len);
  r.message_len = static_cast<uint16_t>(message_len);
  r.backtrace_len = static_cast<uint16_t>(backtrace_len);
  r.method_len = static_cast<uint8_t>(method_len);
  r.steering_len = static_cast<uint8_t>(steering_len);
  r.body_len = static_cast<uint16_t>(body_len);
  r.body_full_len = static_cast<uint32_t>(f.body_full);
  spell_fingerprint(r.fingerprint, fingerprint_of(f));
  spell_fingerprint(r.app_build, app_build_hash());
  r.dynamic_len = static_cast<uint32_t>(peer_len + class_len + target_len + message_len +
                                        backtrace_len + method_len + steering_len + body_len);
  lg.pending.append(reinterpret_cast<const char*>(&r), sizeof r);
  if (peer_len != 0) lg.pending.append(static_cast<const char*>(f.peer), peer_len);
  if (class_len != 0) lg.pending.append(f.exception_class, class_len);
  if (target_len != 0) lg.pending.append(f.request_target, target_len);
  if (message_len != 0) lg.pending.append(f.message, message_len);
  if (backtrace_len != 0) lg.pending.append(f.backtrace, backtrace_len);
  if (method_len != 0) lg.pending.append(f.method, method_len);
  if (steering_len != 0) lg.pending.append(f.steering, steering_len);
  if (body_len != 0) lg.pending.append(f.body, body_len);
}

// The server's own fault, spelled the same way at every call site: one
// error-log record, class Webmachine::Error/17, never reaching the answer.
// One internal failure as one record. The three views and the status
// travelled together through eight arguments - see #std-first.
struct ErrorLine {
  std::string_view peer;           // the socket's address, already spelled
  std::string_view request_target; // RFC 9112 3.2
  std::string_view why;            // no RFC: ours, and it never repeats the request
  uint16_t status_code = 0;        // RFC 9110 15
};

inline void log_internal_error(Logger& lg, const ErrorLine& line) {
  if (!lg.enabled) return;
  const void* peer = line.peer.data();
  const size_t peer_len = line.peer.size();
  const char* request_target = line.request_target.data();
  const size_t request_target_len = line.request_target.size();
  const uint16_t status_code = line.status_code;
  const char* why = line.why.data();
  const size_t why_len = line.why.size();
  ErrFacts f;
  f.peer = peer;
  f.peer_len = peer_len;
  f.request_target = request_target;
  f.request_target_len = request_target_len;
  f.exception_class = "Webmachine::Error";
  f.exception_class_len = 17;
  f.message = why;
  f.message_len = why_len;
  f.status_code = status_code;
  log_error(lg, f);
}

// Which build this is. mruby's enable_debug defines MRB_DEBUG and the
// ship configs do not, so this is the build's own word for itself and
// not a second switch to keep in step with the first.
#ifdef MRB_DEBUG
inline constexpr bool kDebugBuild = true;
#else
inline constexpr bool kDebugBuild = false;
#endif

// The raise half of the facts, read off the VM. Defined in resource.cpp,
// which is where a VM is. The caller has already filled what it knows of
// the request and owns `backtrace`, which the facts point into - so the
// caller can hash the whole and hand the same hash to the page and to
// log_error, instead of the two computing it apart from each other.
void exception_facts(mrb_state* mrb, ErrFacts& f, std::string& backtrace);

// A raise with no request around it: a stream that was answered long ago
// and is now running app code of its own (SSE, a WebSocket). There is no
// target and no method to name, so the fingerprint is the build, the
// class and the place - which is exactly what such a failure is.
inline void log_raise(Logger& lg, mrb_state* mrb, uint16_t status_code) {
  if (!lg.enabled) return;
  ErrFacts f;
  std::string backtrace;
  f.status_code = status_code;
  exception_facts(mrb, f, backtrace);
  if (f.exception_class == nullptr) return;
  log_error(lg, f);
}
}

namespace webmachine::http {
// RFC 9110 5.1: case-insensitive equality against a lowercase literal.
constexpr bool tok_eq(const char* s, size_t n, const char* lit, size_t litn) {
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// RFC 9110 13.1.1/13.1.2: If-Match / If-None-Match spell "any" as *.
constexpr bool star_value(const char* v, size_t n) {
  if (n == 1 && v[0] == '*') return true;
  return n == 3 && v[0] == '"' && v[1] == '*' && v[2] == '"';
}

// RFC 9110 4.2.1: the query is not part of the path.
inline size_t path_only(const char* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (p[i] == '?') return i;
  }
  return n;
}

// RFC 9110 9.1: methods are case-sensitive tokens.
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

// RFC 9110 8.3: text/* without parameters gets charset=utf-8. Setup only,
// and EVERY writer goes through here.
inline std::string with_charset(const std::string& type) {
  if (type.size() < 5 || !tok_eq(type.data(), 5, "text/", 5)) return type;
  if (type.find(';') != std::string::npos) return type;
  return type + "; charset=utf-8";
}

// A literal's length, at compile time.
constexpr size_t clen(const char* s) {
  size_t n = 0;
  while (s[n] != '\0') n++;
  return n;
}
// RFC 6839 / RFC 9110 8.3: is a body of this type worth compressing?
// Structural, conservative downward, decided once per resource.
constexpr bool compressible_media_type(const char* v, size_t n) {
  size_t tn = 0;
  while (tn < n && v[tn] != ';') tn++;
  if (tn >= 5 && tok_eq(v, 5, "text/", 5)) return true;
  if (tn >= 5 && tok_eq(v + tn - 5, 5, "+json", 5)) return true;
  if (tn >= 4 && tok_eq(v + tn - 4, 4, "+xml", 4)) return true;
  constexpr const char* kExact[] = {
      "application/json", "application/javascript", "application/xml",
      "application/wasm", "image/svg+xml",
  };
  for (const char* lit : kExact) {
    if (tok_eq(v, tn, lit, clen(lit))) return true;
  }
  return false;
}
// RFC 6839: the same question, from a std::string.
inline bool compressible_media_type(const std::string& v) {
  return compressible_media_type(v.data(), v.size());
}
namespace proof {
// The table's own self-check, at compile time.
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
}

// RFC 9110 15: the status names.
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

inline constexpr char kDatePlaceholder[] = "Sun, 00 Jan 1970 00:00:00 GMT";
inline constexpr size_t kDateLen = sizeof(kDatePlaceholder) - 1;

// Two digits, zero-padded, at out[0..1].
inline void write_two_digits(char* out, int v) {
  out[0] = static_cast<char>('0' + v / 10);
  out[1] = static_cast<char>('0' + v % 10);
}

// RFC 9110 5.6.7: IMF-fixdate by hand - strftime would obey the locale.
inline void date_core(char out[kDateLen], const struct tm& tm) {
  static const char kDay[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  std::memcpy(out, kDay[tm.tm_wday], 3);
  out[3] = ',';
  out[4] = ' ';
  write_two_digits(out + 5, tm.tm_mday);
  out[7] = ' ';
  std::memcpy(out + 8, kMon[tm.tm_mon], 3);
  out[11] = ' ';
  const int year = tm.tm_year + 1900;
  write_two_digits(out + 12, year / 100);
  write_two_digits(out + 14, year % 100);
  out[16] = ' ';
  write_two_digits(out + 17, tm.tm_hour);
  out[19] = ':';
  write_two_digits(out + 20, tm.tm_min);
  out[22] = ':';
  write_two_digits(out + 23, tm.tm_sec);
  out[25] = ' ';
  std::memcpy(out + 26, "GMT", 3);
}

// RFC 9110 8.6: "Content-Length: N\r\n\r\n", spelled by hand.
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

enum class ClStatus : uint8_t { kOk, kBad, kOverflow };
// RFC 9110 8.6: 1*DIGIT. kBad is the caller's 400, kOverflow its 413.
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

// RFC 9110: the ten fields Resource#request hands back by name. The one
// pass over the field array notes WHERE each one sits; a later ask is a bit
// test and an index, never a second walk over the fields.
enum class NamedField : uint8_t {
  kContentType,
  kContentLength,
  kAuthorization,
  kAccept,
  kAcceptEncoding,
  kIfMatch,
  kIfNoneMatch,
  kIfModifiedSince,
  kIfUnmodifiedSince,
  kHost,
  kCount
};

struct NamedFieldIndex {
  // THE INDEX NEVER LEAVES. A stored position is only meaningful for the
  // field array it was taken from, so the only way to read one is to
  // hand that array and its count back in - `find` applies the index
  // itself and answers nullptr for anything it cannot reach. Nobody
  // outside can subscribe `at`, so nobody can apply it to a different
  // array, and the bound stops being an invariant that lives in three
  // other files.
  //
  // The static_assert below fixes the byte WIDTH and nothing else - that
  // kMaxHeaders fits a uint8_t says nothing about whether this
  // request's array is that long, which is what `find` checks.
  //
  // Declared, not defined: phr_header is incomplete here (see the
  // forward declaration at the top of this file), so the body sits in
  // request.cpp where the framer's header has been included.
  const struct phr_header* find(NamedField f, const struct phr_header* hs, size_t n) const;

  constexpr void note(NamedField f, size_t i) {
    // The framer kept no slot for this one (its field array was full), so
    // there is no place to point at and the bit stays clear.
    if (i > 255) return;
    const auto b = static_cast<uint8_t>(f);
    // RFC 9110 5.2: a repeated field is one list, and the FIRST occurrence
    // is where it starts. A second Host is the framer's 400, not ours.
    if (((present >> b) & 1u) != 0) return;
    present = static_cast<uint16_t>(present | (1u << b));
    at[b] = static_cast<uint8_t>(i);
  }
  constexpr bool carries(NamedField f) const {
    return ((present >> static_cast<uint8_t>(f)) & 1u) != 0;
  }

 private:
  // One bit per NamedField. A field the request did not carry has no
  // position, and the bit is how that is said.
  uint16_t present = 0;
  // Its place in the field array. kMaxHeaders is 64, so a byte holds it.
  uint8_t at[static_cast<size_t>(NamedField::kCount)] = {};
};
struct ReqValues {
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
  const char* range = nullptr;
  size_t range_len = 0;
  const char* if_range = nullptr;
  size_t if_range_len = 0;

  // Handed to a callback that declared the parameter: b8 gets
  // Authorization (RFC 9110 11.6.2), b5 gets Content-Type (8.3).
  const char* authorization = nullptr;
  size_t authorization_len = 0;
  const char* content_type = nullptr;
  size_t content_type_len = 0;
  // The values the 1:1 runtime reads: c4 negotiates against Accept
  // (12.5.1), request.base_uri and request.cookies read Host (7.2) and
  // Cookie (RFC 6265).
  const char* accept = nullptr;
  size_t accept_len = 0;
  const char* host = nullptr;
  size_t host_len = 0;
  const char* cookie = nullptr;
  size_t cookie_len = 0;
  // If-Unmodified-Since / If-Modified-Since, parsed at the switch
  // (5.6.7); valid only when the facts' if_unmodified_since_valid/if_modified_since_valid bit says.
  int64_t if_unmodified_since_epoch = 0;
  int64_t if_modified_since_epoch = 0;
  NamedFieldIndex named;
};

// #210: the fields this request steered by, one per line, for the error
// record and the fingerprint over it. These are the ones the server reads
// BECAUSE they change the answer - which is why ReqValues holds them at
// all. Referer and User-Agent sit beside them in that struct and are not
// here: they are the access log's, and they steer nothing.
//
// Authorization is named by its SCHEME and never by what follows it
// (RFC 9110 11.6.2; the schemes are Basic 7617, Bearer 6750, Digest
// 7616, and whatever else the IANA registry grows). Which scheme ran
// decides which code ran; the credential decides nothing and belongs in
// no file. Cookie is named without its value for the same reason.
inline void spell_steering(const ReqValues* v, std::string& out) {
  out.clear();
  if (v == nullptr) return;
  const char* p = nullptr;
  size_t n = 0;
  const auto put = [&out](const char* name, const char* val, size_t len) {
    if (val == nullptr || len == 0) return;
    out.append(name);
    out.append(": ", 2);
    out.append(val, len);
    out.push_back('\n');
  };
  put("accept", v->accept, v->accept_len);
  put("accept-encoding", v->accept_encoding, v->accept_encoding_len);
  put("content-type", v->content_type, v->content_type_len);
  put("host", v->host, v->host_len);
  put("range", v->range, v->range_len);
  put("if-range", v->if_range, v->if_range_len);
  put("if-match", v->if_match, v->if_match_len);
  put("if-none-match", v->if_none_match, v->if_none_match_len);
  // The scheme is the first token; a line with no space is a scheme on
  // its own, which is all that goes down either way.
  if (v->authorization != nullptr && v->authorization_len != 0) {
    p = v->authorization;
    n = 0;
    while (n < v->authorization_len && p[n] != ' ' && p[n] != '\t') n++;
    put("authorization", p, n);
  }
  if (v->cookie != nullptr && v->cookie_len != 0) put("cookie", "sent", 4);
}


// A run of digits at v[i], cursor left on the first that is not one.
// False = none there, or the value does not fit a size_t.
inline bool read_size(const char* v, size_t n, size_t& i, size_t* out) {
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
}

enum class RangeParse : uint8_t { kNone, kOne, kUnsat };
// RFC 9110 14.1.2: ONE range over the SELECTED representation's octets.
// kNone means act as if the field were absent (14.2 permits it).
inline RangeParse parse_range(const char* v, size_t n, size_t complete, size_t* first,
                              size_t* last) {
  if (n < 7 || !tok_eq(v, 6, "bytes=", 6)) return RangeParse::kNone;
  size_t i = 6;
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  size_t a = 0, b = 0;
  const bool have_a = read_size(v, n, i, &a);
  if (i >= n || v[i] != '-') return RangeParse::kNone;
  i++;
  const bool have_b = read_size(v, n, i, &b);
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  if (i != n) return RangeParse::kNone;
  if (!have_a && !have_b) return RangeParse::kNone;
  if (complete == 0) return RangeParse::kUnsat;
  if (!have_a) {
    if (b == 0) return RangeParse::kUnsat;
    *first = b >= complete ? 0 : complete - b;
    *last = complete - 1;
    return RangeParse::kOne;
  }
  if (have_b && b < a) return RangeParse::kNone;
  if (a >= complete) return RangeParse::kUnsat;
  *first = a;
  *last = have_b ? (b < complete - 1 ? b : complete - 1) : complete - 1;
  return RangeParse::kOne;
}

// RFC 9110 14.2: ONE validator, compared strongly; a date reads as no match.
inline bool if_range_matches(const char* v, size_t n, const char* tag, size_t taglen) {
  size_t i = 0;
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  size_t e = n;
  while (e > i && (v[e - 1] == ' ' || v[e - 1] == '\t')) e--;
  return e - i == taglen && std::memcmp(v + i, tag, taglen) == 0;
}

// RFC 9110 12.5.3: may gzip be sent? Most specific wins; an absent field
// never reaches this parse.
inline bool gzip_acceptable(const char* v, size_t n) {
  bool gz_seen = false, gz_ok = false, star_seen = false, star_ok = false;
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
    const size_t ts = i;
    while (i < n && v[i] != ',' && v[i] != ';' && v[i] != ' ' && v[i] != '\t') i++;
    const size_t tl = i - ts;
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

// RFC 9110 13.1.1/13.1.2: strong for If-Match, weak for If-None-Match.
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
      while (i < n && v[i] != ',') i++;
      continue;
    }
    const size_t start = i;
    i++;
    while (i < n && v[i] != '"') i++;
    if (i >= n) break;
    i++;
    const size_t mlen = i - start;
    if ((weak || !member_weak) && mlen == taglen &&
        std::memcmp(v + start, tag, taglen) == 0) {
      return true;
    }
  }
  return false;
}

// Exactly k digits at p[at], as one number. -1 = one of them is not a digit.
inline int read_fixed_digits(const char* p, size_t at, size_t k) {
  int v = 0;
  for (size_t i = 0; i < k; i++) {
    if (p[at + i] < '0' || p[at + i] > '9') return -1;
    v = v * 10 + (p[at + i] - '0');
  }
  return v;
}

// The three-letter month name at p[at], 1..12. -1 = none of them.
inline int read_month_name(const char* p, size_t at) {
  static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  for (int m = 0; m < 12; m++) {
    if (std::memcmp(p + at, kMon[m], 3) == 0) return m + 1;
  }
  return -1;
}

// days_from_civil (Howard Hinnant): proleptic Gregorian, no libc.
inline int64_t epoch_from_civil(int y, int m, int d, int hh, int mm, int ss) {
  y -= m <= 2;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const int yoe = y - era * 400;
  const int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const int64_t days = int64_t{era} * 146097 + doe - 719468;
  return days * 86400 + hh * 3600 + mm * 60 + ss;
}

// RFC 9110 5.6.7: an HTTP-date in any of its three forms - IMF-fixdate
// ("Sun, 06 Nov 1994 08:49:37 GMT"), obsolete RFC 850
// ("Sunday, 06-Nov-94 08:49:37 GMT") and asctime
// ("Sun Nov  6 08:49:37 1994") - to Unix seconds. False = not a date.
inline bool parse_http_date(const char* p, size_t n, int64_t* out) {
  int y, mo, d, hh, mm, ss;
  if (n == 29 && p[3] == ',' && p[4] == ' ') {  // IMF-fixdate
    d = read_fixed_digits(p, 5, 2);
    mo = read_month_name(p, 8);
    y = read_fixed_digits(p, 12, 4);
    hh = read_fixed_digits(p, 17, 2);
    mm = read_fixed_digits(p, 20, 2);
    ss = read_fixed_digits(p, 23, 2);
    if (std::memcmp(p + 25, " GMT", 4) != 0) return false;
  } else if (n >= 28 && n <= 33 && std::memcmp(p + n - 4, " GMT", 4) == 0 &&
             static_cast<const char*>(std::memchr(p, ',', n)) != nullptr) {  // RFC 850
    const char* c = static_cast<const char*>(std::memchr(p, ',', n));
    const size_t at = static_cast<size_t>(c - p) + 2;
    if (at + 18 + 4 != n || at + 18 > n) return false;
    d = read_fixed_digits(p, at, 2);
    if (p[at + 2] != '-' || p[at + 6] != '-') return false;
    mo = read_month_name(p, at + 3);
    y = read_fixed_digits(p, at + 7, 2);
    if (y >= 0) y += y < 70 ? 2000 : 1900;  // 5.6.7's two-digit rule
    hh = read_fixed_digits(p, at + 10, 2);
    mm = read_fixed_digits(p, at + 13, 2);
    ss = read_fixed_digits(p, at + 16, 2);
  } else if (n == 24 && p[3] == ' ' && p[7] == ' ') {  // asctime
    mo = read_month_name(p, 4);
    d = p[8] == ' ' ? read_fixed_digits(p, 9, 1) : read_fixed_digits(p, 8, 2);
    hh = read_fixed_digits(p, 11, 2);
    mm = read_fixed_digits(p, 14, 2);
    ss = read_fixed_digits(p, 17, 2);
    y = read_fixed_digits(p, 20, 4);
  } else {
    return false;
  }
  if (y < 0 || mo < 0 || d <= 0 || d > 31 || hh < 0 || hh > 23 || mm < 0 || mm > 59 ||
      ss < 0 || ss > 60) {
    return false;
  }
  *out = epoch_from_civil(y, mo, d, hh, mm, ss);
  return true;
}

// RFC 9110 12.5.1: choose among the provided types given an Accept
// value - q-values and both wildcard forms, most specific match per
// type, highest q wins, the provided ORDER breaks ties (webmachine
// conneg semantics). -1 = nothing acceptable (406). `types` may carry
// parameters; matching reads only the type/subtype half.
inline int choose_media_type(const std::string* types, size_t ntypes, const char* av,
                             size_t alen) {
  struct Range {
    const char* t;
    size_t tn;
    const char* sub;
    size_t sn;
    int q1000;
  };
  Range ranges[32];
  size_t nr = 0;
  size_t i = 0;
  while (i < alen && nr < 32) {
    while (i < alen && (av[i] == ' ' || av[i] == '\t' || av[i] == ',')) i++;
    if (i >= alen) break;
    const size_t start = i;
    while (i < alen && av[i] != ',') i++;
    const size_t end = i;
    int q = 1000;
    size_t semi = start;
    while (semi < end && av[semi] != ';') semi++;
    size_t tend = semi;
    while (tend > start && (av[tend - 1] == ' ' || av[tend - 1] == '\t')) tend--;
    size_t pi = semi;
    while (pi < end) {
      pi++;
      while (pi < end && (av[pi] == ' ' || av[pi] == '\t')) pi++;
      if (pi + 2 <= end && (av[pi] == 'q' || av[pi] == 'Q') && av[pi + 1] == '=') {
        size_t v = pi + 2;
        int whole = 0, frac = 0, fdig = 0;
        if (v < end && (av[v] >= '0' && av[v] <= '9')) {
          whole = av[v] - '0';
          v++;
        }
        if (v < end && av[v] == '.') {
          v++;
          while (v < end && (av[v] >= '0' && av[v] <= '9') && fdig < 3) {
            frac = frac * 10 + (av[v] - '0');
            fdig++;
            v++;
          }
        }
        while (fdig < 3) {
          frac *= 10;
          fdig++;
        }
        q = whole * 1000 + frac;
        if (q > 1000) q = 1000;
      }
      while (pi < end && av[pi] != ';') pi++;
    }
    const char* slash = static_cast<const char*>(std::memchr(av + start, '/', tend - start));
    if (slash != nullptr) {
      ranges[nr].t = av + start;
      ranges[nr].tn = static_cast<size_t>(slash - (av + start));
      ranges[nr].sub = slash + 1;
      ranges[nr].sn = tend - static_cast<size_t>(slash + 1 - av);
      ranges[nr].q1000 = q;
      nr++;
    }
  }
  int best = -1;
  int best_q = 0;
  int best_spec = -1;
  for (size_t t = 0; t < ntypes; t++) {
    const std::string& full = types[t];
    size_t tn = full.find(';');
    if (tn == std::string::npos) tn = full.size();
    while (tn > 0 && full[tn - 1] == ' ') tn--;
    const char* tp = full.data();
    const size_t sl = full.find('/');
    if (sl == std::string::npos || sl >= tn) continue;
    const size_t main_n = sl;
    const char* sub_p = tp + sl + 1;
    const size_t sub_n = tn - sl - 1;
    int q = -1;
    int spec = -1;
    for (size_t r = 0; r < nr; r++) {
      const Range& rg = ranges[r];
      int this_spec;
      if (rg.tn == 1 && rg.t[0] == '*') {
        this_spec = 0;
      } else if (!tok_eq(rg.t, rg.tn, tp, main_n)) {
        continue;
      } else if (rg.sn == 1 && rg.sub[0] == '*') {
        this_spec = 1;
      } else if (tok_eq(rg.sub, rg.sn, sub_p, sub_n)) {
        this_spec = 2;
      } else {
        continue;
      }
      if (this_spec > spec) {
        spec = this_spec;
        q = rg.q1000;
      }
    }
    if (spec < 0 || q == 0) continue;
    if (q > best_q || (q == best_q && spec > best_spec)) {
      best = static_cast<int>(t);
      best_q = q;
      best_spec = spec;
    }
  }
  return best;
}

// RFC 9110 8.8.3: spell an application-supplied ETag for the wire - an
// already-quoted or weak form passes verbatim, bare bytes are quoted
// (webmachine ETag.new semantics).
inline void etag_spell(const char* raw, size_t n, std::string& out) {
  out.clear();
  if ((n >= 2 && raw[0] == '"') || (n >= 3 && raw[0] == 'W' && raw[1] == '/')) {
    out.append(raw, n);
    return;
  }
  out.push_back('"');
  out.append(raw, n);
  out.push_back('"');
}

// RFC 3986 5.3, the n11 subset: join create_path onto a base. A full
// URI passes verbatim; an absolute-path ref replaces the base's path;
// a relative segment appends after the base's last '/'.
inline void uri_join(const char* base, size_t blen, const char* path, size_t payload_length,
                     std::string& out) {
  out.clear();
  if (payload_length >= 8 && std::memcmp(path, "http", 4) == 0) {
    const char* colon = static_cast<const char*>(std::memchr(path, ':', payload_length));
    if (colon != nullptr && static_cast<size_t>(colon - path) <= 5) {
      out.append(path, payload_length);
      return;
    }
  }
  if (payload_length > 0 && path[0] == '/') {
    size_t slashes = 0, i = 0;
    for (; i < blen; i++) {
      if (base[i] == '/') {
        slashes++;
        if (slashes == 3) break;
      }
    }
    out.append(base, i);
    out.append(path, payload_length);
    return;
  }
  size_t cut = blen;
  while (cut > 0 && base[cut - 1] != '/') cut--;
  if (cut == 0) cut = blen;
  out.append(base, cut);
  if (!out.empty() && out.back() != '/') out.push_back('/');
  out.append(path, payload_length);
}

// RFC 9110 5.1 / 5.6.2: a field name is a token. Every byte an app can
// put into an answer's head passes one of the two writers that call this
// - response.cpp's Headers#[]= and resource.cpp's `field` - so this is
// where the shape is decided and nowhere after. Without it an app that
// answers `generate_etag` with "v1\r\nSet-Cookie: a=b", or names an
// options() key with a CRLF in it, splices whole fields into the answer
// - and an app that echoes a request header into a response one hands
// that splice to whoever sent the request.
inline bool field_name_ok(const char* p, size_t n) {
  if (n == 0) return false;
  for (size_t i = 0; i < n; i++) {
    const unsigned char c = static_cast<unsigned char>(p[i]);
    const bool tchar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' ||
                       c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
                       c == '-' || c == '.' || c == '^' || c == '_' || c == '`' ||
                       c == '|' || c == '~';
    if (!tchar) return false;
  }
  return true;
}

// RFC 9110 5.5: a field value carries no CR, no LF and no NUL. Obs-fold
// is gone from HTTP/1.1 (RFC 9112 5.2) and RFC 9113 8.2.1 makes either
// byte a malformed h2 field, so one rule serves both writers.
inline bool field_value_ok(const char* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (p[i] == '\r' || p[i] == '\n' || p[i] == '\0') return false;
  }
  return true;
}

// RFC 9110 5.1: a field name is known by its length first. The switches
// below have a case for these and no other, so a name of any other length is
// none of them - one shift and one test, before a byte is compared. The mask
// is derived from the list, so a new case cannot forget to widen it.
constexpr uint32_t lengths_mask(const size_t* v, size_t n) {
  uint32_t m = 0;
  for (size_t i = 0; i < n; i++) m |= 1u << v[i];
  return m;
}
constexpr bool length_is_one_of(size_t nlen, uint32_t mask) {
  return nlen < 32 && ((mask >> nlen) & 1u) != 0;
}

// RFC 9110: dnt(3) host(4) range(5) accept/cookie(6) sec-gpc(7)
// if-match/if-range(8) content-type(12) authorization/if-none-match(13)
// accept-charset(14) accept-encoding/accept-language(15)
// if-modified-since(17) if-unmodified-since(19).
inline constexpr size_t kFieldLengths[] = {3, 4, 5, 6, 7, 8, 12, 13, 14, 15, 17, 19};
inline constexpr uint32_t kFieldLengthMask =
    lengths_mask(kFieldLengths, sizeof(kFieldLengths) / sizeof(kFieldLengths[0]));

// RFC 9110: ONE length-switch per header. The 9110 facts are filled here;
// true means the name is not one of them and the framer must read it.
static inline bool header_switch(const char* name, size_t nlen, const char* value, size_t vlen,
                                 flow::ReqFacts& facts, ReqValues& vals, size_t at) {
  if (!length_is_one_of(nlen, kFieldLengthMask)) return true;
  switch (nlen) {
    case 3:
      if (tok_eq(name, nlen, "dnt", 3)) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return false;
      }
      break;
    case 4:
      if (tok_eq(name, nlen, "host", 4)) {
        // The VALUE is 9110's (request.base_uri reads it); the
        // presence check stays the framer's (9112 requires Host), so
        // this arm both keeps the bytes AND falls through to the wire
        // functor.
        vals.host = value;
        vals.host_len = vlen;
        vals.named.note(NamedField::kHost, at);
        break;
      }
      break;
    case 5:
      if (tok_eq(name, nlen, "range", 5)) {
        vals.range = value;
        vals.range_len = vlen;
        return false;
      }
      break;
    case 6:
      if (tok_eq(name, nlen, "accept", 6)) {
        facts.has_accept = true;
        facts.plain = false;
        vals.accept = value;
        vals.accept_len = vlen;
        vals.named.note(NamedField::kAccept, at);
        return false;
      }
      if (tok_eq(name, nlen, "cookie", 6)) {
        vals.cookie = value;
        vals.cookie_len = vlen;
        return false;
      }
      break;
    case 7:
      if (tok_eq(name, nlen, "sec-gpc", 7)) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return false;
      }
      break;
    case 8:
      if (tok_eq(name, nlen, "if-range", 8)) {
        vals.if_range = value;
        vals.if_range_len = vlen;
        return false;
      }
      if (tok_eq(name, nlen, "if-match", 8)) {
        facts.has_if_match = true;
        facts.plain = false;
        facts.if_match_star = star_value(value, vlen);
        vals.if_match = value;
        vals.if_match_len = vlen;
        vals.named.note(NamedField::kIfMatch, at);
        return false;
      }
      break;
    case 12:
      if (tok_eq(name, nlen, "content-type", 12)) {
        // RFC 9110 8.3: b5's argument and accept_helper's key.
        vals.content_type = value;
        vals.content_type_len = vlen;
        vals.named.note(NamedField::kContentType, at);
        return false;
      }
      break;
    case 13:
      if (tok_eq(name, nlen, "authorization", 13)) {
        // RFC 9110 11.6.2: b8's argument.
        vals.authorization = value;
        vals.authorization_len = vlen;
        vals.named.note(NamedField::kAuthorization, at);
        return false;
      }
      if (tok_eq(name, nlen, "if-none-match", 13)) {
        facts.has_if_none_match = true;
        facts.plain = false;
        facts.if_none_match_star = star_value(value, vlen);
        vals.if_none_match = value;
        vals.if_none_match_len = vlen;
        vals.named.note(NamedField::kIfNoneMatch, at);
        return false;
      }
      break;
    case 14:
      if (tok_eq(name, nlen, "accept-charset", 14)) {
        facts.has_accept_charset = true;
        facts.plain = false;
        return false;
      }
      break;
    case 15:
      if (tok_eq(name, nlen, "accept-language", 15)) {
        facts.has_accept_language = true;
        facts.plain = false;
        return false;
      }
      if (tok_eq(name, nlen, "accept-encoding", 15)) {
        facts.has_accept_encoding = true;
        facts.plain = false;
        vals.accept_encoding = value;
        vals.accept_encoding_len = vlen;
        vals.named.note(NamedField::kAcceptEncoding, at);
        return false;
      }
      break;
    case 17:
      if (tok_eq(name, nlen, "if-modified-since", 17)) {
        facts.has_if_modified_since = true;
        facts.plain = false;
        // 13.1.3: an unparseable date reads as "field absent" (l14).
        vals.named.note(NamedField::kIfModifiedSince, at);
        facts.if_modified_since_valid = parse_http_date(value, vlen, &vals.if_modified_since_epoch);
        // 13.1.3: a date in the future is ignored (l15).
        if (facts.if_modified_since_valid) {
          facts.if_modified_since_future =
              vals.if_modified_since_epoch > ::time(nullptr);
        }
        return false;
      }
      break;
    case 19:
      if (tok_eq(name, nlen, "if-unmodified-since", 19)) {
        facts.has_if_unmodified_since = true;
        facts.plain = false;
        // 13.1.4: same rule as IMS (h11).
        vals.named.note(NamedField::kIfUnmodifiedSince, at);
        facts.if_unmodified_since_valid =
            parse_http_date(value, vlen, &vals.if_unmodified_since_epoch);
        return false;
      }
      break;
    default:
      break;
  }
  return true;
}
}

namespace webmachine {
// RFC 9110 3.4: one request message, as the parser left it - every field
// LENT, nothing copied, valid for the frame that dispatches it. This is
// what a run may read; it is not what a run may keep.
struct ReqView {
  // RFC 9112 3.2 / RFC 9113 8.3.1: the request-target, and how much of it
  // is RFC 3986 3.3's path.
  const char* request_target = nullptr;
  size_t request_target_len = 0;
  size_t path_len = 0;
  // RFC 9110 9: the method, folded to what the flow branches on and kept
  // verbatim for what has to spell it back (405's Allow, the access line).
  flow::Method method = flow::Method::kGet;
  const char* method_token = nullptr;
  size_t method_token_len = 0;
  // No RFC: this server's route table and what the match captured.
  const RouteTable* table = nullptr;
  int route = -1;
  RouteSpans spans {};
  // RFC 9110 6.3: the header field section, in the parser's own layout.
  // Only request.headers reads it - it is the one caller that asked for
  // ALL of them. Every named accessor reads `values` instead.
  const void* fields = nullptr;
  size_t field_count = 0;
  // Where the one pass found the ten fields Resource#request names. The
  // field array is walked once; answering request.accept by walking it
  // again would be that same work a second time.
  const http::ReqValues* values = nullptr;
  // RFC 9110 6.4: the request's content, LENT for the frame like
  // everything else here - the framer collected it (bounded by its own
  // 413) and it dies with the dispatch. Null = no content arrived.
  const char* content = nullptr;
  size_t content_len = 0;
};

void request_init(mrb_state* mrb, struct RClass* wm);

void request_bind(const ReqView* view);

// RFC 9110 12.5: the ReqValues a parked h2 stream no longer has, re-derived
// from the fields it copied. Cold, and it lives in request.cpp so that
// h2_dispatch stays header_switch's only caller in http2.cpp - two callers
// there and the switch stops being inlined into the hot path.
void values_of_copied_fields(const ::phr_header* fields, size_t n, http::ReqValues& out);

// RFC 9110: n11's create_path names a new disp_path for THIS run;
// request_bind clears the override. request.cpp owns the storage.
void request_disp_override(const char* p, size_t n);
}

namespace webmachine {
// WEBMACHINE'S NAMES, AND THEY STAY. Every cb_* below is a callback of
// webmachine-ruby's Webmachine::Resource::Callbacks, spelled exactly as
// an app spells it - content_types_provided, generate_etag,
// moved_permanently?, post_is_create?. That IS the contract; RFC 9110
// names none of them, it only says what each one decides (the clause
// sits in kFlow, one per node). Which is why the abbreviations went:
// cb_ct_provided was not a name an app could grep for.
//
// The run_* slots below are ours and no source names them: they hold what
// ONE request's callbacks produced, are reset at frame entry, and keep
// their capacity across requests on purpose.
// A C++ resource callback. Arguments arrive as ARGUMENTS, never through
// mrb_get_args, so the function never reads the callinfo and may be
// entered straight from C++ - which is what makes it cheaper than the
// same callback written in Ruby, instead of dearer.
using NativeCb = mrb_value (*)(mrb_state* mrb, mrb_value self, mrb_int argc,
                               const mrb_value* argv);

// Define one on a resource class. Ruby can still call it - a wrapper is
// registered as an ordinary method - but the fold records the raw
// pointer, and the engine calls THAT.
void define_native(mrb_state* mrb, struct RClass* c, mrb_sym sym, NativeCb fn,
                   mrb_aspec aspec = MRB_ARGS_ANY());

// #210: a run may hand over one of these (response.error_asset). The
// definition is further down, with the tier that owns it - a run only
// ever passes the handle on.
struct AssetEntry;

// #30: how many watchers one connection may run. It is what fits in the
// tag's spare byte, and 256 is far past anything a connection has reason
// to hold.
inline constexpr unsigned kMaxWatchers = 256;

struct Resource {
  flow::KonstSet konst;
  mrb_state* mrb = nullptr;
  struct RClass* klass = nullptr;
  // The class's own class - where a `def self.x` lives. Kept because
  // entering such a method directly needs the class it was found in, and
  // the fold freezes klass, so this pointer is as stable as klass itself.
  struct RClass* meta_klass = nullptr;
  uint64_t dynamic = 0;
  mrb_sym node_sym[flow::kNodeCount] = {};
  mrb_method_t node_m[flow::kNodeCount] = {};
  bool node_irep[flow::kNodeCount] = {};
  NativeCb node_native[flow::kNodeCount] = {};
  // One bit per node: its callback answers on the CLASS, not on the live
  // instance. Same reason as ValueCb::on_class - the method is resolved
  // once, here, and never searched again.
  uint64_t node_on_class = 0;
  bool dynamic_body = false;
  bool gzip_offered = false;
  // The engine frame is entered as a C++ call, not a Ruby one: no
  // hidden class, no proc, no per-resource object for the GC to mark.
  bool init_needed = false;
  // mruby: the initialize the fold RESOLVED, entered directly by the run.
  // Object's is undef'd on Webmachine::Resource, so init_needed is simply
  // "the author wrote one" - and mrb_obj_new is never used, because it
  // would search for this same method twice per request (mrb_func_basic_p,
  // then mrb_funcall_argv) to arrive where the fold already stands.
  mrb_method_t init_m = {};
  bool init_irep = false;
  enum mrb_vtype live_tt = MRB_TT_OBJECT;
  mutable mrb_value live = {};
  mutable const flow::ReqFacts* run_facts = nullptr;
  mutable std::string* run_body = nullptr;
  mutable bool run_have_body = false;
  // #210 response.error_asset: THE ENTRY, not its bytes. The error assets
  // are mmap'd for the life of the process, and both writers already know
  // how to put a mapped entry on the wire - Assets::wire_len/wire_iov/
  // copy_wire on h1, Content::Src::kAsset on h2 - so this run hands over
  // the same handle the asset tier hands over, and nothing is rooted,
  // copied or released for it.
  mutable const AssetEntry* run_asset = nullptr;
  mutable uint16_t run_status = 0;
  // Zero-copy hand-off: at or above run_zc_min bytes the body handler's
  // own String is frozen and rooted and LENT to the writer, instead of
  // being copied into run_body. 0 = never lend, which is every caller
  // that does not pass a threshold.
  mutable size_t run_zc_min = 0;
  mutable mrb_value run_zc = {};
  mutable bool run_zc_have = false;

  // How many arguments each node's callback ASKED for, read once at
  // fold from its own signature. webmachine-ruby hands several of them
  // one - is_authorized?(header), uri_too_long?(uri),
  // known_content_type?(type), valid_content_headers?(headers),
  // valid_entity_length?(length) - and a method that declared the
  // parameter must not be called with nothing.
  uint8_t node_argc[flow::kNodeCount] = {};

  // A VALUE callback: it answers with a String/Array/Time/Hash the
  // engine marshals into C++ right after the yield, not with a
  // truthiness the graph consumes. Resolved at fold like every other
  // callback; `has` false = webmachine-ruby's default stands in C++.
  struct ValueCb {
    bool has = false;
    mrb_sym sym = {};
    mrb_method_t m = {};
    bool irep = false;
    // A C++ callback registered through define_native, and the reason it
    // is a SEPARATE pointer rather than "call the cfunc we resolved":
    // mruby hands a cfunc its arguments through the callinfo the VM
    // pushed (vm.c: check_argument_count, then MRB_METHOD_FUNC(m)(mrb,
    // self)), so calling one from a C++ frame gives it the CALLER's
    // registers and mrb_get_args reads a stranger's. Only a function
    // whose convention we set can be entered directly - the same trick
    // the VM plays on mrb_attr_reader, which it recognises by pointer.
    NativeCb native = nullptr;
    // Which receiver: the live instance, or the class itself. The fold
    // resolves BOTH kinds, so neither is looked up again per request - an
    // undefined m used to be the marker for "class-only", and it cost a
    // full mrb_funcall_argv every time it was read.
    bool on_class = false;
    uint8_t argc = 0;
  };
  ValueCb cb_known_methods;   // instance-level; class-level folds konst
  ValueCb cb_allowed_methods;
  ValueCb cb_content_types_provided;     // instance content_types_provided
  ValueCb cb_content_types_accepted;     // content_types_accepted (accept_helper)
  ValueCb cb_options;         // b3: Hash of extra response fields
  ValueCb cb_variances;       // Vary's tail (helpers.rb variances)
  ValueCb cb_generate_etag;            // generate_etag
  ValueCb cb_last_modified;
  ValueCb cb_expires;
  ValueCb cb_moved_permanently;      // i4/k5: String/URI = Location + 301
  ValueCb cb_moved_temporarily;      // l5: String/URI = Location + 307
  ValueCb cb_post_is_create;  // n11's fork
  ValueCb cb_create_path;
  ValueCb cb_base_uri;
  ValueCb cb_process_post;
  ValueCb cb_finish_request;  // after the walk, ALWAYS (fsm.rb ensure)

  // The old fast part, back: `dynamic` above answers "is this flow NODE
  // decided by the VM" in one load; `cb_mask` is the same idea for "does
  // this value callback exist", one bit per ValueCb above, so a node
  // handler that only needs the yes/no (most calls, most of the time)
  // never has to load the ValueCb struct itself - the payload (sym/m/
  // irep/argc) is only touched once the bit says the answer is yes. Set
  // once at fold, read every run.
  enum CbBit : uint32_t {
    kCbKnownMethods = 1u << 0,
    kCbAllowedMethods = 1u << 1,
    kCbContentTypesProvided = 1u << 2,
    kCbContentTypesAccepted = 1u << 3,
    kCbOptions = 1u << 4,
    kCbVariances = 1u << 5,
    kCbGenerateEtag = 1u << 6,
    kCbLastModified = 1u << 7,
    kCbExpires = 1u << 8,
    kCbMovedPermanently = 1u << 9,
    kCbMovedTemporarily = 1u << 10,
    kCbPostIsCreate = 1u << 11,
    kCbCreatePath = 1u << 12,
    kCbBaseUri = 1u << 13,
    kCbProcessPost = 1u << 14,
    kCbFinishRequest = 1u << 15,
  };
  uint32_t cb_mask = 0;

  // Konst-folded content_types_provided: [type, handler] in the
  // resource's own order, [0] the default choice (c3 with no Accept).
  // Never empty after fold - the default is [["text/html", :to_html]].
  struct TypedHandler {
    std::string type;
    mrb_sym handler = {};
    mrb_method_t m = {};
    bool irep = false;
    NativeCb native = nullptr;
    // cb.rb: a handler written as `def self.x` is asked ONCE, at setup -
    // the same rule the first pair has always followed. `baked` is what it
    // answered; without it a negotiated second type would look the handler
    // up on the INSTANCE and find whatever Object happens to define.
    std::string baked;
    bool has_baked = false;
  };
  std::vector<TypedHandler> content_types_provided;

  // Per-request slots for the RUNTIME tier, all reset by resource_run
  // at frame entry. `run_headers` takes the field lines this request
  // produced; the writer appends it between the prebuilt head and
  // Content-Length, which is exactly where the prebuilt head stops, so
  // no prebuilt byte moves.
  mutable std::string* run_headers = nullptr;
  mutable const http::ReqValues* run_vals = nullptr;
  mutable const ReqView* run_req = nullptr;
  // response.code= / response.do_redirect (response.cpp writes these;
  // the flow's halt seeds run_resp_code, finish_request may change it
  // - fsm.rb's respond order).
  mutable uint16_t run_resp_code = 0;
  mutable bool run_redirect = false;
  // The conneg choice when the head cannot stay prebuilt: non-empty
  // means the writer spells THIS Content-Type in a dynamic head
  // instead of using the baked prefix. Empty = prebuilt path,
  // byte-identical to today.
  //
  // There is no second flag saying "the head went dynamic", because there
  // is nothing a flag could say that these two buffers do not: a run needs
  // its own head exactly when it negotiated a Content-Type (this) or
  // produced a field line (run_headers). It used to be a bool as well, set
  // at eight places, and BOTH writers had to OR it with run_headers being
  // non-empty - which is the proof that it never carried the second half
  // by itself. One of the eight places forgot to set it, and nothing
  // broke, for the same reason.
  mutable std::string run_content_type;
  // n11: create_path's override of request.disp_path.
  mutable std::string run_disp_path;
  mutable bool run_disp_set = false;
  // response.file = "rel/path": the NAME only. Nothing is opened here - the
  // reactor does that through the ring, so a callback never blocks on a
  // disk. run_file_bad is a name this process refused before the kernel saw
  // it (empty, embedded NUL); it answers 404 in the SAME shape a rejected
  // resolve does, so neither is distinguishable from a plain miss.
  mutable std::string run_file;
  mutable bool run_have_file = false;
  mutable bool run_file_bad = false;
  // #202: what a `def self.x` ANSWERED, once, while the app was being set
  // up. That is what the class form is for - the value belongs to the
  // process, not to a request, so no request ever enters the VM for it.
  // `asked` says the class form existed and was evaluated; `present` says
  // its answer was neither nil nor false.
  struct KonstValue {
    bool asked = false;
    bool present = false;
    std::string text;   // RFC 9110 8.8.3: the ETag, already spelled
    int64_t epoch = 0;  // RFC 9110 5.6.7: the moment, for the date fields
  };
  KonstValue konst_etag;
  KonstValue konst_last_modified;
  KonstValue konst_expires;
  // #202: whether this resource has ANY of the three caching answers to
  // give - a class form that answered at setup, or a callback still to
  // ask. Decided once when the resource is baked, because the answer
  // cannot change afterwards, and o18 asks it on every GET.
  bool has_caching = false;

  // Once-per-run memos: generate_etag / last_modified / expires are
  // asked at most ONCE (g11+k13+o18 share etag; h12+l17+o18 share
  // last_modified), whatever the graph visits.
  mutable bool etag_asked = false;
  mutable bool etag_present = false;
  mutable std::string etag_value;  // spelled, quoted form
  mutable bool last_modified_asked = false;
  mutable bool last_modified_present = false;
  mutable int64_t last_modified_epoch = 0;
  mutable bool expires_asked = false;
  mutable bool expires_present = false;
  mutable int64_t expires_epoch = 0;
  // Marshalled once per run where the app answered dynamically;
  // capacity survives across requests.
  // The dynamic content_types_provided, marshalled from the app's Array.
  // It SURVIVES the run on purpose: the handler's method is resolved here,
  // and re-resolving it per request is a method search per request on the
  // path that renders every body. marshal_ct compares the app's fresh
  // answer against this and only rebuilds when it actually differs - which
  // for every resource that answers the same list each time is never.
  mutable std::vector<TypedHandler> run_content_types_provided;
  mutable bool run_content_types_marshalled = false;
  mutable std::vector<std::string> run_methods;
  mutable std::vector<std::string> run_variances;
};

bool resource_fold(mrb_state* mrb, mrb_value klass, Resource& out, char* err, size_t errlen);

// One request as a bound run receives it: what the parse settled, the
// header values the calling frame still holds (none where that frame is
// already gone), the bytes themselves, and the smallest body worth LENDING
// rather than copying - 0 where nothing downstream could hold a lend.
struct BoundRequest {
  const flow::ReqFacts& facts;
  const http::ReqValues* vals;
  const ReqView* req;
  size_t zc_min = 0;
};

// Where a bound run writes what it produced: the body it spelled, whether
// it spelled one at all, and the field lines it named.
struct RunAnswer {
  std::string* body;
  bool* have_body;
  std::string* headers;
};

uint16_t resource_run(const Resource& res, const BoundRequest& asked,
                      const RunAnswer& answer);

bool resource_exception_take(const Resource& res, mrb_value* out);

// The body a bound run LENT rather than copied: the value the connection
// has to hold until its send drains, and the bytes it may point at.
bool resource_body_lent(const Resource& res, mrb_value* v, const char** ptr, size_t* len);

// Hand a lent body back - the only legal end of the window opened above.
void resource_body_unlend(mrb_state* mrb, mrb_value v);

// Did this run name a file instead of spelling a body? Same hand-off shape
// as resource_body_lent: the run is over, so the slot leaves the Resource.
bool resource_file_wanted(const Resource& res, const char** ptr, size_t* len, bool* bad);

// RFC 9110: Webmachine::Response - the object a runtime callback
// writes to. Handles over the run slots above, nothing owns storage;
// response.cpp owns every line. response_bind mirrors request_bind:
// the run frame points it at THIS run's Resource, and at nothing
// after it.
void response_init(mrb_state* mrb, struct RClass* wm);
void response_bind(const Resource* res);
// Assets is declared further down - this only needs the name.
class Assets;
void response_bind_error_assets(Assets* a);

// Webmachine::Watcher - a description, never a registration. Ruby builds
// one and hands it back; the server arms it. The mask, the abort flag and
// the handle live in its CDATA and NOT in its iv table, which holds
// exactly the two things a GC has to see: the source and the block.
void watcher_init_class(mrb_state* mrb, struct RClass* wm);
bool watcher_p(mrb_state* mrb, mrb_value v);
unsigned watcher_events_mask(mrb_value v);
bool watcher_aborted_p(mrb_value v);
int watcher_fd(mrb_value v);
int watcher_slot(mrb_value v);
void watcher_set_slot(mrb_value v, int slot);
void watcher_armed(mrb_value v, struct io_uring* ring);
void watcher_disarm(mrb_value v);
mrb_value watcher_source_of(mrb_state* mrb, mrb_value v);
mrb_value watcher_block_of(mrb_state* mrb, mrb_value v);
}

namespace webmachine::gzip {
inline constexpr unsigned char kHeader[10] = {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff};

// RFC 1951/1952: a dynamic body, level 1, raw deflate. False means serve
// identity - compression never fails a response.
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
  strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  strm.avail_in = static_cast<uInt>(in.size());
  strm.next_out = reinterpret_cast<Bytef*>(&out[0]) + body_off;
  strm.avail_out = static_cast<uInt>(bound);
  const int rc = deflate(&strm, Z_FINISH);
  const size_t produced = strm.total_out;
  deflateEnd(&strm);
  if (rc != Z_STREAM_END) return false;
  out.resize(body_off + produced);

  const uint32_t crc = static_cast<uint32_t>(
      crc32_z(0, reinterpret_cast<const Bytef*>(in.data()), in.size()));
  const uint32_t isize = static_cast<uint32_t>(in.size());
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
}

namespace webmachine {
// RFC 9110 8.3: Content-Type needs a media type, and the mapping from a
// file's extension to one is NOT specified by any RFC - it is the
// platform's database (mime.types / shared-mime-info). This class is that
// lookup and says which file answered, because the answer differs per host.
class MimeDb {
 public:
  bool load(const char* configured, char* err, size_t errlen);
  // RFC 9110 8.3: which media-type database answered.
  const std::string& source() const { return source_; }
  // RFC 9110 8.3: how many extensions it holds.
  size_t size() const { return by_ext_.size(); }
  const char* type_of(const std::string& name) const;

 private:
  void take(const char* type, size_t tlen, const char* ext, size_t elen);
  void parse_types(const char* p, const char* end);
  void parse_globs2(const char* p, const char* end);

  std::vector<std::pair<std::string, std::string>> by_ext_;
  std::string source_;
};

// TWO sources, and the split runs right through this struct. The STORE is
// a ZIP file, so the stored fields carry PKWARE APPNOTE 4.3.7's names for
// them (file name, file data, compressed size, uncompressed size, CRC-32,
// method 8 = deflate, RFC 1951). What we ANSWER with is HTTP, so the
// derived fields carry RFC 9110's:
//   etag           RFC 9110 8.8.3
//   last_modified  RFC 9110 8.8.2
//   content_type   RFC 9110 8.3
//   gzip_*         RFC 1952 2.2/2.3 - the 10 header and 8 trailer octets
//                  that turn ZIP's raw deflate stream into a gzip member
// The heads are prebuilt because they never vary per request except in
// their Date (RFC 9110 6.6.1), which is why each one remembers where its
// Date sits and which second it spells.
struct AssetEntry {
  std::string file_name;
  const char* file_data = nullptr;
  size_t compressed_size = 0;
  size_t uncompressed_size = 0;
  uint32_t crc32 = 0;
  bool deflated = false;
  bool last_modified_valid = false;
  char etag[10] = {};
  char last_modified[http::kDateLen] = {};
  std::string content_type;
  // APPNOTE 4.5: the pack's own extra field 0x574D, which holds the whole
  // <img> for this picture - src, size and alt - as a page emits it. Null
  // on an entry that carries none.
  const char* img_tag = nullptr;
  size_t img_tag_len = 0;

  // RFC 9112 2.1: a status-line and a header section, complete, ending in
  // the empty line - everything of a response except its content.
  struct Head {
    std::string bytes;
    size_t date_offset = 0;
    time_t unix_seconds = 0;
  };
  Head head_200[3];  // RFC 9110 15.3.1
  Head head_304[3];  // RFC 9110 15.4.5

  unsigned char gzip_header[10] = {};
  unsigned char gzip_trailer[8] = {};

  std::string h2_head_200;  // RFC 9113 8.3 / RFC 7541: the same, encoded
  std::string h2_head_304;
};

// PKWARE APPNOTE: the store. One mapping of one ZIP file, its entries
// sorted, answered from RAM. Everything this class emits is RFC 9110's,
// so its own vocabulary has to stay clear of HTTP's: the three prebuilt
// head flavours differ ONLY in their Connection field line (RFC 9110
// 7.6.1, "connection option"), which is why they are not called variants
// - RFC 9110 12.1 already means something else by that word.
class Assets {
 public:
  enum ConnectionOption : uint8_t { kNoConnectionField = 0, kKeepAlive = 1, kConnClose = 2 };
  static constexpr const char* kConnectionLine[3] = {"", "Connection: keep-alive\r\n",
                                                     "Connection: close\r\n"};

  Assets() = default;
  ~Assets();
  Assets(const Assets&) = delete;
  Assets& operator=(const Assets&) = delete;

  bool open(const char* zip_path, const MimeDb& mime, char* err, size_t errlen);

  AssetEntry* find(const char* path, size_t len);

  uint16_t verdict(const AssetEntry& e, flow::Method m, const flow::ReqFacts& f,
                   const http::ReqValues& vals) const;

  // Everything this tier needs to spell one head: the entry it describes,
  // the status it carries, whether the connection stays open, the Date
  // line for this second and the second it stands for, the satisfied range
  // where the status is 206, and - where the caller already holds an error
  // page - the type and length that page must be declared with. The page's
  // bytes are the caller's to append: this tier spells heads and lends its
  // own file data, and a page is neither.
  struct HeadAsk {
    AssetEntry& entry;
    uint16_t status_code = 0;
    ConnectionOption conn = kNoConnectionField;
    const char* date = nullptr;
    time_t unix_seconds = 0;
    size_t first_byte_pos = 0;
    size_t last_byte_pos = 0;
    const char* body_type = nullptr;
    size_t body_len = 0;
  };

  void answer_head(const HeadAsk& ask, std::string& sink);
  void answer_206_head(const HeadAsk& ask, std::string& sink);
  void answer_416_head(const HeadAsk& ask, std::string& sink);

  // RFC 1952 2.2: the wire body's length - the deflate stream plus the 10
  // header and 8 trailer octets of a gzip member, or the stored bytes
  // alone when nothing was deflated.
  static size_t wire_len(const AssetEntry& e) {
    return e.deflated ? e.compressed_size + 18 : e.compressed_size;
  }
  // RFC 1952 2.2: [off, off+n) of that body WITHOUT copying it, which is
  // why it returns a COUNT: a gzip member is three separate spans - our
  // header, the mapping, our trailer - so one logical window is up to
  // THREE iovecs, and only the middle one is the file.
  static unsigned wire_iov(const AssetEntry& e, size_t off, size_t n, struct iovec* iov);
  static void copy_wire(const AssetEntry& e, size_t off, size_t n, std::string& sink);

  // ZIP (APPNOTE): the entry table, for the h2 setup half.
  std::vector<AssetEntry>& entries() { return entries_; }

 private:
  const AssetEntry* find_exact(const char* name, size_t len) const;
  static void patch_date(AssetEntry::Head& h, const char* date, time_t unix_seconds);

  // munmap(addr, length) - the names of the arguments they become.
  const char* map_addr_ = nullptr;
  size_t map_length_ = 0;
  std::vector<AssetEntry> entries_;
  AssetEntry::Head s405_[3];  // RFC 9110 15.5.6
  AssetEntry::Head s406_[3];  // RFC 9110 15.5.7
};

// RFC 9110 15: what a status is called and who registered it. reason()
// spells the name the status LINE carries; these two answer the page's
// question, which is not the same set - 15 of the 54 statuses with a
// page are vendor inventions, and the page says so.
// XDG Base Directory Specification over FHS: where the shipped error
// pack is looked for when nobody named one. Empty when there is none -
// a missing picture is no reason not to start.
std::string error_assets_path(const char* configured);

const char* status_title(uint16_t status);
const char* status_source(uint16_t status);

// #210: the error resource. Always there, never routed - the route that
// produced the error calls it, so an error is delivered by whoever made
// it and not by a second trip through the router. A handler is named
// to_<ext>_error, the way an ordinary resource names to_html, and this
// holds the ones Webmachine::ErrorResource actually answers to.
//
// Rendered PER RESPONSE: a 404 names what was not found, so the set of
// bodies is the set of request targets and there is nothing a boot could
// have prepared.
class ErrorPages {
 public:
  ErrorPages() = default;
  ~ErrorPages();
  ErrorPages(const ErrorPages&) = delete;
  ErrorPages& operator=(const ErrorPages&) = delete;

  // One instance of the class, and the handlers it answers to. A class
  // that answers to none, or that raises being built, is a startup
  // refusal with a name.
  bool open(mrb_state* mrb, Assets* assets, char* err, size_t errlen);
  bool ready() const { return ready_; }

  // RFC 9110 12.5.1: which form this client can read, as an index into
  // what the error resource offers. -1 when it offers nothing.
  int media_for(uint16_t status, const char* accept, size_t len) const;
  // The picture IS the answer for an image form: not rendered, lent out
  // of the error assets's mapping. nullptr when this slot is not one, or when
  // this status has no cat.
  const char* pack_body(uint16_t status, int slot, size_t* len) const;
  // #210: the page for a status in a form, rendered once at boot and
  // lent from there. Every 4xx is one of these - it names no failure and
  // repeats nothing the client sent, so two answers with the same status
  // are the same bytes. Null for a status no page was prepared for, and
  // for any answer that has something of its own to say.
  const char* prepared_body(uint16_t status, int slot, size_t* len) const;
  const char* media_type(int slot) const;
  bool named_ours(const char* accept, size_t len) const;
  static bool names_anything(const char* accept, size_t len);

  // fsm.rb handle_exception, on the error resource and nowhere else.
  bool exception_text(mrb_value exc, std::string& out);

  // What ONE answer adds to the status. Nothing the client sent is in
  // here: a page that repeated the target back would be reflecting a
  // request into a document, and the target is in the error log, which
  // is where a request belongs. What is left is ours - what
  // handle_exception made of the exception, and the fingerprint of the
  // failure, which is what a user can read out and an operator can grep.
  struct Fields {
    const char* message = nullptr;
    size_t message_len = 0;
    const char* backtrace = nullptr;
    size_t backtrace_len = 0;
    // kFingerprintLen hex digits, not terminated. Null on a page that
    // stands for no failure - every 4xx.
    const char* fingerprint = nullptr;
  };
  // false when there is no page to offer - the caller still owes an
  // answer and falls back to the bodyless status.
  bool render(uint16_t status, int slot, const Fields& f, std::string& out);
  // The bytes this status answers with, whichever way this build has
  // them: the picture where the error assets hold one, the page prepared
  // at boot where the answer names no failure of its own, a render where
  // it does. `held` is the caller's storage and is used for that last
  // case only - the other two are lent where they lie. Null when this
  // build can spell no page at all.
  const char* body_for(uint16_t status, int slot, const Fields& f, std::string& held, size_t* len);

 private:
  struct Handler {
    mrb_sym sym = 0;
    std::string type;
    // An image form is answered from the error assets, so no method is called
    // and none has to exist.
    bool from_pack = false;
  };
  struct Cat {
    const AssetEntry* entry = nullptr;
  };
  void read_cats(Assets& assets);
  void read_prepared();

  mrb_state* mrb_ = nullptr;
  mrb_value res_ = mrb_nil_value();
  mrb_sym exc_sym_ = 0;
  std::vector<Handler> have_;
  // The same strings again, laid out the way choose_media_type wants them.
  std::vector<std::string> types_;
  // The way out when Accept matches nothing offered: text/plain, by name.
  int plain_ = 0;
  // And what a client with no Accept at all gets: the first form that is
  // not a picture.
  int html_ = 0;
  // Both tables below are indexed by status - kFirstError: an answer under
  // 400 did not fail and has no page, and 600 is not a status.
  static constexpr uint16_t kFirstError = 400;
  static constexpr uint16_t kPastLastError = 600;
  // The same shape the status store uses: a slot per status into a dense
  // list, 0 for the statuses these error assets has no picture for.
  std::vector<Cat> cats_;
  std::array<int16_t, kPastLastError - kFirstError> cat_index_ {};
  // One page per status and rendered form, status-major with a row of
  // have_.size(). 0 in the index is "this status has none prepared".
  std::vector<std::string> prepared_;
  std::array<int16_t, kPastLastError - kFirstError> prep_index_ {};
  bool ready_ = false;
};
}

#include "h2_wire.hpp"

namespace webmachine {

struct AssetEntry;

// RFC 9113 5.1: one entry per stream in a non-idle state. What a stream
// must remember between frames is exactly what the state machine there
// names - what it has received, what it still owes, and whether either
// half is closed - so the fields are that list and nothing else.
struct H2Stream {
  // RFC 9113 5.1.1: the Stream Identifier every frame carries.
  uint32_t id = 0;
  // RFC 9113 6.9.1: the stream's half of the flow-control window. Signed
  // because a SETTINGS_INITIAL_WINDOW_SIZE change can drive it negative.
  int64_t flow_window = kH2DefaultWindow;
  // RFC 9110 6.4: the request's content. Counted AND kept, because
  // request.body reads it at END_STREAM (RFC 9113 6.1).
  size_t content_received = 0;
  std::string request_content;
  // RFC 9110 8.6: what the sender said it would send, and whether it said.
  size_t content_length = 0;
  bool content_length_given = false;
  // RFC 9113 8.3: a parked request is answered after hdrbuf has been
  // reused by the next dispatch, so its fields cannot be lent the way
  // the immediate path lends them - they are COPIED here instead, names
  // and values end to end in `field_blob` with four offsets each in
  // `field_spans`. Paid only by a request that carries a body, which is
  // already doing more work than a GET.
  std::string field_blob;
  std::vector<uint32_t> field_spans;
  flow::ReqFacts facts;
  // RFC 9113 6.9.1: an answer flow control could not frame yet. The asset
  // and its verdict wait here; the byte range is [first, end).
  const AssetEntry* parked_asset = nullptr;
  uint16_t parked_status = 0;
  size_t parked_first = 0;
  size_t parked_end = 0;
  // RFC 9110 6.4: the response content, in ONE form whatever it is made
  // of. A content this stream owes is a base, a cursor, an end, and -
  // where the base is borrowed - a release obligation; the three sources
  // this replaced differed in nothing else. Carrying them as three
  // parallel triples is what let a release rule live APART from the lend
  // it releases, which is the shape the h1 mapping's use-after-free had.
  struct Content {
    // RFC 9110 8.1: where the representation data comes from.
    enum class Src : uint8_t { kNone, kAsset, kLent, kOwned };
    // kAsset: RFC 1952 framing means one logical range is up to THREE
    // iovecs (gzip header, the stored deflate payload, trailer), so the
    // entry travels and not a pointer.
    const AssetEntry* asset = nullptr;
    const char* lent = nullptr;  // kLent: the handler's frozen String
    std::string owned;           // kOwned: what flow control could not frame
    // RFC 9113 6.9.1: what has already left, against RFC 9110 8.6's total.
    size_t sent = 0;
    size_t length = 0;
    // No RFC: mruby's GC. Non-null EXACTLY while an unroot is owed, and
    // H2State::content_retire is the one place that clears it, so no
    // value is ever unrooted twice.
    mrb_state* mrb = nullptr;
    mrb_value value = {};
    Src src = Src::kNone;
    // RFC 9113 6.9.1: flow control can cut content across many rounds, so
    // "still owes octets" is what keeps the stream - and the lend - alive.
    bool owes() const { return src != Src::kNone && sent < length; }
    void take_asset(const AssetEntry* e, size_t first, size_t end) {
      src = Src::kAsset;
      asset = e;
      sent = first;
      length = end;
    }
    void take_lent(mrb_state* m, mrb_value v, const char* p, size_t n) {
      src = Src::kLent;
      lent = p;
      sent = 0;
      length = n;
      mrb = m;
      value = v;
    }
    void take_owned(const char* p, size_t n) {
      src = Src::kOwned;
      owned.assign(p, n);
      sent = 0;
      length = n;
    }
    void clear() {
      src = Src::kNone;
      asset = nullptr;
      lent = nullptr;
      owned.clear();
      sent = 0;
      length = 0;
    }
  };
  Content response_content;
  // No RFC: this server's route table index.
  uint16_t route = 0;
  // RFC 9113 8.3.1: the :path pseudo-header, which is the request target.
  std::string request_target;
  // RFC 9110 9.3.2: HEAD is GET without content.
  bool head_method = false;
  // RFC 9113 6.2: END_HEADERS has been seen, so the field section is whole.
  bool end_headers = false;
  // RFC 9113 5.1: the peer will send no more DATA on this stream.
  bool half_closed_remote = false;
};

struct H2State {
  struct lshpack_enc enc;
  struct lshpack_dec dec;

  // RFC 9113 6.9.1: the CONNECTION's half of the flow-control window.
  int64_t flow_window = kH2DefaultWindow;
  int64_t peer_initial_window = kH2DefaultWindow;
  uint32_t peer_max_frame = kH2MaxFrameSize;
  uint32_t last_stream = 0;
  uint32_t highest_opened = 0;
  size_t flush_cursor = 0;
  bool goaway_sent = false;
  bool goaway_recv = false;

  std::string frag;
  uint32_t frag_stream = 0;
  uint8_t frag_flags = 0;
  bool frag_active = false;

  std::string hdrbuf;

  std::vector<H2Stream> streams;

  // RFC 7541 2.3.3 / 4.1: every insert into the dynamic table shifts the
  // index of everything older by one. A cached head that REFERENCES an
  // entry is therefore only valid while nothing has been inserted since
  // it was built - and the dynamic path inserts freely (its date, and
  // every field line an app sets). Counted here, compared below: over-
  // counting only costs a rebuild, under-counting would replay an index
  // that has moved.
  uint64_t enc_ins = 0;

  struct {
    std::string bytes;
    size_t head_len = 0;
    uint64_t enc_ins = 0;
    // RFC 7541 6.2.1: the SAME head, spelled with the insert instead of
    // the reference. A dynamic-table entry has to reach the peer once
    // before anything may point at it, and `bytes` is replayed verbatim
    // for the rest of the second - so the response that BUILDS the entry
    // carries this form, and every one after it carries `bytes`.
    std::string prime;
    bool primed = false;
    bool has_data = false;
    uint16_t status = 0;
    uint16_t route = 0xffff;
    time_t sec = 0;
  } head_cache;

  // A body whose LAST bytes are in the round now on the wire: the stream
  // that owned it is gone, but the writer still points at it, so it waits
  // here for the drained-round point (Http1::Conn::zc_release) instead of
  // being unrooted where the stream ended.
  struct Lend {
    mrb_state* mrb;
    mrb_value v;
  };
  std::vector<Lend> retired;

  // ls-hpack: lshpack_enc_init ALLOCATES and returns -1 when it could
  // not - the one call of the four that can fail. Ignoring it left an
  // encoder that was never built, to be handed to lshpack_enc_encode on
  // the first answer. A constructor cannot refuse, so it records, and
  // h2_begin refuses.
  bool hpack_ready = false;
  // RFC 9113: allocated only when the preface was spoken, never before.
  H2State() {
    hpack_ready = lshpack_enc_init(&enc) == 0;
    lshpack_dec_init(&dec);
    lshpack_dec_set_max_capacity(&dec, kH2DecTableSize);
  }
  // RFC 9113: the decoder dies with the connection - and so does every
  // lend the streams still hold. h1's ~Conn, one tier down: unconditional,
  // GOAWAY or error or a client that simply left.
  ~H2State() {
    for (H2Stream& s : streams) content_retire(s);
    content_drain();
    lshpack_enc_cleanup(&enc);
    lshpack_dec_cleanup(&dec);
  }
  H2State(const H2State&) = delete;
  H2State& operator=(const H2State&) = delete;

  // RFC 9113 5.1: a stream in the table is open or half-closed.
  H2Stream* find(uint32_t id) {
    for (H2Stream& st : streams)
      if (st.id == id) return &st;
    return nullptr;
  }
  // RFC 9113 5.1: a stream the connection must remember.
  H2Stream& open(uint32_t id) {
    if (H2Stream* st = find(id)) return *st;
    streams.emplace_back();
    H2Stream& st = streams.back();
    st.id = id;
    st.flow_window = peer_initial_window;
    return st;
  }
  // RFC 9113 5.1: content leaves the stream when the stream does. Clearing
  // `mrb` HERE is what makes a second call a no-op, so no value is ever
  // unrooted twice - and the content is cleared whole, so an asset or an
  // owned buffer cannot outlive the stream that framed it either.
  void content_retire(H2Stream& s) {
    if (s.response_content.mrb != nullptr) {
      retired.push_back(Lend{s.response_content.mrb, s.response_content.value});
      s.response_content.mrb = nullptr;
    }
    s.response_content.clear();
  }
  // THE release: called where a whole round has drained, so nothing the
  // kernel was handed still points into these Strings.
  void content_drain() {
    for (const Lend& l : retired) resource_body_unlend(l.mrb, l.v);
    retired.clear();
  }
  // RFC 9113 5.1: the number stays, the entry goes.
  void close_stream(uint32_t id) {
    for (size_t i = 0; i < streams.size(); i++) {
      if (streams[i].id == id) {
        // The move-assign below DISCARDS this entry's members: a body it
        // still holds has to leave first, or its root leaks silently on
        // every close - RST_STREAM, END_STREAM and error paths alike.
        content_retire(streams[i]);
        streams[i] = std::move(streams.back());
        streams.pop_back();
        return;
      }
    }
  }
};
}

namespace webmachine {
namespace wsdeflate {
inline constexpr uint8_t kMinRawWindowBits = 9;

inline constexpr unsigned char kSyncTail[4] = {0x00, 0x00, 0xff, 0xff};

struct Params {
  bool on = false;
  bool server_no_context_takeover = false;
  bool client_no_context_takeover = false;
  uint8_t server_max_window_bits = 15;
  uint8_t client_max_window_bits = 15;
};

namespace detail {
// RFC 9110 5.6.3: optional whitespace.
constexpr bool is_ows(char c) { return c == ' ' || c == '\t'; }

// RFC 9110 5.6.2: token, which is what 7692 4.2's params are.
constexpr bool is_tchar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
         c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' ||
         c == '~';
}

// RFC 9110 5.1: case-insensitive equality for an extension parameter name.
inline bool ci_eq(const char* s, size_t n, const char* lit, size_t litn) {
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// RFC 7692 7.1.2.1: 8..15, no leading zeroes - "08" is a refusal.
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
}

// RFC 7692 4.2/5.1: one Sec-WebSocket-Extensions value, answered with the
// FIRST offer this endpoint can accept. Declining is never an error.
inline bool negotiate(const char* v, size_t len, Params& out, std::string& answer) {
  size_t i = 0;
  while (i < len) {
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
      i++;
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
          i++;
          pv = v + i;
          while (i < len && v[i] != '"') {
            if (v[i] == '\\' && i + 1 < len) i++;
            i++;
          }
          pv_len = static_cast<size_t>(v + i - pv);
          if (i < len) i++;
        } else {
          pv = v + i;
          while (i < len && detail::is_tchar(v[i])) i++;
          pv_len = static_cast<size_t>(v + i - pv);
        }
      }
      if (!ok) continue;

      if (detail::ci_eq(v + pn_at, pn_len, "server_no_context_takeover", 26)) {
        if (seen_snct || have_value) { ok = false; continue; }
        seen_snct = true;
        p.server_no_context_takeover = true;
      } else if (detail::ci_eq(v + pn_at, pn_len, "client_no_context_takeover", 26)) {
        if (seen_cnct || have_value) { ok = false; continue; }
        seen_cnct = true;
        p.client_no_context_takeover = true;
      } else if (detail::ci_eq(v + pn_at, pn_len, "server_max_window_bits", 22)) {
        uint8_t b = 0;
        if (seen_smwb || !have_value || !detail::window_bits(pv, pv_len, b) ||
            b < kMinRawWindowBits) {
          ok = false;
          continue;
        }
        seen_smwb = true;
        p.server_max_window_bits = b;
      } else if (detail::ci_eq(v + pn_at, pn_len, "client_max_window_bits", 22)) {
        if (seen_cmwb) { ok = false; continue; }
        seen_cmwb = true;
        if (have_value) {
          uint8_t b = 0;
          if (!detail::window_bits(pv, pv_len, b)) { ok = false; continue; }
          p.client_max_window_bits = b;
          echo_cmwb = true;
        }
      } else {
        ok = false;
      }
    }

    if (ok) {
      out = p;
      answer.assign("permessage-deflate");
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
    while (i < len && v[i] != ',') i++;
  }
  return false;
}
// RFC 7692 7: the codec itself lives in wsconn.cpp - it is the only
// file that codes a frame. Params and negotiate stay here because the
// h1 upgrade path negotiates the extension before a WsConn exists.
class Codec;
}
}

namespace webmachine {
inline constexpr size_t kMaxWsMessageDefault = 64u * 1024;

struct WsResource;

struct WsConn;

bool ws_fold(mrb_state* mrb, mrb_value klass, WsResource& out, char* err, size_t errlen);

bool ws_wants_deflate(const WsResource* r);
WsResource* ws_resource_new();
void ws_resource_free(WsResource* r);

void ws_init(mrb_state* mrb, struct RClass* wm);

WsConn* ws_admit(const WsResource* r, Logger* elog, std::string& proto, uint16_t& status);

void ws_open(WsConn* c, const wsdeflate::Params& deflate);

bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink);

void ws_free(WsConn* c);
}

namespace webmachine {
struct SseResource;

struct SseStream;

bool sse_fold(mrb_state* mrb, mrb_value klass, SseResource& out, char* err, size_t errlen);
SseResource* sse_resource_new();
void sse_resource_free(SseResource* r);

void sse_init(mrb_state* mrb, struct RClass* wm);

SseStream* sse_open(const SseResource* r, Logger* elog, uint16_t& status);

bool sse_second(SseStream* s, int64_t now_s, std::string& sink);

void sse_free(SseStream* s);
}

namespace webmachine {
namespace ws {
enum : uint8_t {
  kContinuation = 0x0,
  kText = 0x1,
  kBinary = 0x2,
  kClose = 0x8,
  kPing = 0x9,
  kPong = 0xa,
};

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

inline constexpr size_t kMaxControlPayload = 125;

bool accept_key(const char* key, size_t key_len, char out[28]);

// RFC 6455 5.2: everything the fourteen header bytes decide on their own -
// the reserved bits, the opcode, the mask bit, the length encoding, and
// what a control frame may not be. Pure, because begin_frame used to judge
// these one at a time while already writing the refusal for the first one
// that failed, and because these are the Autobahn cases: they deserve a
// table, not a socket.
struct Head {
  // No RFC: our verdict on the header, which 6455 5.1 turns into a close.
  enum class Err : uint8_t { kNone, kProtocol, kTooBig };
  Err err = Err::kNone;
  uint8_t opcode = 0;           // RFC 6455 5.2: Opcode
  uint64_t payload_length = 0;  // RFC 6455 5.2: Payload length
  // RFC 6455 5.2: where the four Masking-key octets start, which is where
  // the length encoding ended.
  uint8_t masking_key_at = 0;
  bool fin = false;   // RFC 6455 5.2: FIN
  bool rsv1 = false;  // RFC 6455 5.2: RSV1, negotiated by RFC 7692
  bool control = false;  // RFC 6455 5.5: opcode has the high bit
};

// RFC 6455 5.2: how many header octets the NEXT decision needs, given how
// many have arrived. Two to see the length encoding and the mask bit, then
// two or eight more for an extended Payload length, then four for the
// Masking-key. Pure and here, not in the reader, because read_head reads
// all of them unconditionally - so this is the ONE thing that has to be
// true before read_head may be called at all.
inline uint8_t header_need(const unsigned char* h, uint8_t have) {
  if (have < 2) return 2;
  const uint8_t len7 = static_cast<uint8_t>(h[1] & 0x7f);
  const uint8_t ext = len7 == 126 ? 2 : (len7 == 127 ? 8 : 0);
  return static_cast<uint8_t>(2 + ext + ((h[1] & 0x80) != 0 ? 4 : 0));
}

// RFC 6455 5.3: transformed-octet-i = original-octet-i XOR
// masking-key-octet-(i MOD 4). Copying, not in place, because every caller
// is already moving the octets somewhere - into the control buffer, into
// the inflate window, into a test's own buffer - and doing both in one
// pass is what the reader did before this was a function.
// `key_at` is i's offset within the frame, so a payload delivered in
// pieces keeps the key aligned across recvs.
inline void unmask_copy(char* dst, const char* src, size_t n, const unsigned char key[4],
                        size_t key_at) {
  for (size_t i = 0; i < n; i++) {
    dst[i] = static_cast<char>(src[i] ^ key[(key_at + i) & 3]);
  }
}

inline Head read_head(const unsigned char* h, bool have_codec) {
  Head o;
  const unsigned char b0 = h[0];
  const unsigned char b1 = h[1];
  o.fin = (b0 & 0x80) != 0;
  o.rsv1 = (b0 & 0x40) != 0;
  o.opcode = static_cast<uint8_t>(b0 & 0x0f);
  o.control = (o.opcode & 0x08) != 0;
  // RFC 6455 5.2: RSV2 and RSV3 are never negotiated here, and RSV1 only
  // where a codec was.
  if ((b0 & 0x30) != 0) { o.err = Head::Err::kProtocol; return o; }
  if (o.rsv1 && !have_codec) { o.err = Head::Err::kProtocol; return o; }
  switch (o.opcode) {
    case kContinuation:
    case kText:
    case kBinary:
    case kClose:
    case kPing:
    case kPong: break;
    default: o.err = Head::Err::kProtocol; return o;
  }
  // RFC 7692 6: the per-message bit rides the FIRST frame of a data
  // message and nothing else.
  if (o.rsv1 && (o.control || o.opcode == kContinuation)) {
    o.err = Head::Err::kProtocol;
    return o;
  }
  // RFC 6455 5.1: every client frame is masked.
  if ((b1 & 0x80) == 0) { o.err = Head::Err::kProtocol; return o; }
  o.payload_length = static_cast<uint64_t>(b1 & 0x7f);
  o.masking_key_at = 2;
  // RFC 6455 5.2: the shortest encoding that fits, and the top bit of a
  // 64-bit length is reserved.
  if (o.payload_length == 126) {
    o.payload_length = (static_cast<uint64_t>(h[2]) << 8) | h[3];
    o.masking_key_at = 4;
    if (o.payload_length < 126) { o.err = Head::Err::kProtocol; return o; }
  } else if (o.payload_length == 127) {
    o.payload_length = 0;
    for (int i = 0; i < 8; i++) o.payload_length = (o.payload_length << 8) | h[2 + i];
    o.masking_key_at = 10;
    if (o.payload_length <= 0xffff || (o.payload_length >> 63) != 0) { o.err = Head::Err::kProtocol; return o; }
  }
  // RFC 6455 5.5: a control frame is short and never fragmented.
  if (o.control && (o.payload_length > kMaxControlPayload || !o.fin)) {
    o.err = Head::Err::kProtocol;
    return o;
  }
  return o;
}

// RFC 6455 5.4 and 7.4.1: may this frame join the message in flight? Four
// scalars are all the connection state that decides it - which is why it
// can be a table too.
inline Head::Err admit(const Head& h, uint8_t msg_op, bool msg_deflated, uint64_t msg_len,
                       uint64_t max_message) {
  if (h.control) return Head::Err::kNone;
  if (h.opcode == kContinuation) {
    if (msg_op == 0) return Head::Err::kProtocol;  // continues nothing
    // A deflated message is bounded after inflation, not here.
    if (!msg_deflated && msg_len + h.payload_length > max_message) return Head::Err::kTooBig;
    return Head::Err::kNone;
  }
  if (msg_op != 0) return Head::Err::kProtocol;  // interleaved data frames
  if (!h.rsv1 && h.payload_length > max_message) return Head::Err::kTooBig;
  return Head::Err::kNone;
}

size_t build_header(uint8_t opcode, bool fin, bool rsv1, size_t payload_len, char head[10]);

size_t build_close_payload(uint16_t code, const char* reason, size_t reason_len,
                           char out[125]);

bool read_close(const char* payload, size_t len, uint16_t& code, const char** reason,
                size_t* reason_len);
}
}

namespace webmachine {
struct WsResource;
struct WsConn;
namespace wsdeflate { struct Params; }
WsConn* ws_admit(const WsResource* r, Logger* elog, std::string& proto, uint16_t& status);
bool ws_wants_deflate(const WsResource* r);
void ws_open(WsConn* c, const wsdeflate::Params& deflate);
bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink);
void ws_free(WsConn* c);

struct SseResource;
struct SseStream;
SseStream* sse_open(const SseResource* r, Logger* elog, uint16_t& status);
bool sse_second(SseStream* s, int64_t now_s, std::string& sink);
void sse_free(SseStream* s);

struct H2State;
void h2_free(H2State* h2);

class Assets;
struct AssetEntry;

inline constexpr size_t kMaxHead = 8192;
// #210: the one path the error assets answer under. Reserved, so an
// operator's own tree can never collide with it.
inline constexpr char kErrorAssetsPrefix[] = "/error_assets/";
inline constexpr size_t kErrorAssetsPrefixLen = sizeof(kErrorAssetsPrefix) - 1;
inline constexpr size_t kMaxBody = 1u << 20;
inline constexpr size_t kMaxHeaders = 64;
static_assert(kMaxHeaders <= 255, "http::NamedFieldIndex::at holds a field's place in one byte");
inline constexpr size_t kCompressFloor = 1280;
inline constexpr size_t kDeliverChunk = 64u * 1024;

inline constexpr size_t kWarmBudgetDefault = kDeliverChunk;

// At or above this many bytes a dynamic body is LENT to the writer instead
// of copied into the send buffer. 128 KiB and not 64: through the real ring
// the measured win at 64 KiB (+7.5%) sits inside the harness's own +/-10%
// spread and is not a number a default can be defended with, while 128 KiB
// (+25%) is several times that noise. At and below 32 KiB lending is a small
// net LOSS, and a wrong-direction default silently regresses every
// deployment that never tunes it - so the default errs high. 0 turns lending
// off and every body is copied, exactly as before.
inline constexpr size_t kZeroCopyDefault = 128u * 1024;
// A ceiling on what an operator may ask for, so a typo cannot quietly mean
// "never lend": beyond this a body is larger than anything this tier serves.
// 1 GiB and not 2, so it still fits an mrb_int on a 32-bit-integer build -
// the TOML range check is spelled in mrb_int, and a wrapped bound would
// refuse every value instead of refusing none.
inline constexpr size_t kZeroCopyMax = 1u << 30;

// response.file reads a WINDOW at a time, the way the asset tier already
// delivers (see Http1::more's st.xfer arm), so per-connection memory is
// O(window) and not O(file). A file smaller than this is still one read and
// one round, exactly as before; a larger one is refilled per drained round.
// There is no ceiling on the file itself any more.
// Where a response.file transfer stands. ONE field, five values: the
// combinations three separate bools could spell - and did spell wrongly -
// are not representable. kDone is the state that made the difference: the
// last lend is ON THE WIRE, so the mapping may not be handed back yet, and
// the drained round after it is the one that cleans up.
enum class FileStage : uint8_t { kNone, kNamed, kRing, kDeliver, kDone };

// What the next round of a transfer does. Computed by file_step() from a
// snapshot and by nothing else; applied by file_apply() and by nothing
// else. A POD returned in registers - purity here is about the DECISION,
// never about the bytes, which stay exactly where they are.
// NO RFC - a round of delivery is this server's decision, not HTTP's. The
// quantities it decides about are HTTP's, and it shares three names with
// its h2 twin H2SendStep ON PURPOSE: start, give and the fact that a round
// is measured in bytes offered, not bytes owned.
struct FileStep {
  // The source is NAMED, not pointed at - the same shape H2SendStep uses,
  // and for the same reason: a round is a decision about which bytes, and
  // an address is an answer to a different question.
  enum class Src : uint8_t { kNone, kWindow, kMapping };
  Src src = Src::kNone;
  size_t start = 0;       // RFC 9110 6.4: first byte of the content this
                          // round lends
  size_t give = 0;        // how many - the same word H2SendStep uses
  size_t sent_after = 0;  // RFC 9110 8.6: content_sent once it lands
  FileStage next = FileStage::kNone;
  bool head = false;         // RFC 9112 2.1: rides the first round only
  bool release_map = false;  // munmap: off the wire, may go back
  bool log = false;          // the ONE access line of this transfer
  bool clear = false;        // the transfer is over
  bool persist = true;       // RFC 9112 9.3
};

inline constexpr size_t kResponseFileWindow = 256u * 1024;

// From this size up a file is MAPPED and handed to one send instead of being
// read window by window: the kernel walks the mapping itself, so there is no
// read into user space and no window buffer at all. Below it the mmap/munmap
// pair - two syscalls the ring cannot carry - costs more than the reads it
// saves. The crossover is a property of the machine, so it is a [tune] knob:
// 0 is the operator saying "never map", which is a real answer.
inline constexpr size_t kFileMapDefault = 1u * 1024 * 1024;
// The same ceiling kZeroCopyMax carries, for the same reason: it has to fit
// an mrb_int on a 32-bit-integer build or the range check refuses everything.
inline constexpr size_t kFileMapMax = 1u << 30;

// The most a mapping lends to ONE send. The kernel caps a single sendmsg
// at MAX_RW_COUNT (INT_MAX rounded down to a page), and a body offered past
// that comes back short - which reads exactly like a dead peer and drops a
// healthy connection. 64 MiB sits under that cap at every page size, costs
// one extra SQE per 64 MiB and not one extra copy, and bounds how long a
// single operation can hold the connection.
// The slowest client this tier will serve a large file to, in bytes per
// second. 16 kbit/s: HALF the slowest throttle a mobile network applies once
// a monthly allowance is spent - Vodafone and O2 drop to 32 kbit/s, Telekom
// to 64, and 128 kbit/s is the common US figure. Half, because the send
// deadline is refreshed per COMPLETED send, so a client running at exactly
// the chunk's own rate would finish it exactly on the deadline.
inline constexpr size_t kSlowClientRate = 2000;
// A send is bounded at both ends. Below: enough for a frame and its head, so
// a very short send_timeout cannot chop the wire into nothing. Above: one
// sendmsg moves at most MAX_RW_COUNT (INT_MAX rounded down to a page), and a
// body offered past that comes back short - indistinguishable from a dead
// peer.
inline constexpr size_t kFileSendChunkMin = 4096;
inline constexpr size_t kFileSendChunkMax = 64u * 1024 * 1024;

// What one send may carry, from the send timeout and the slowest client we
// serve. DERIVED, not chosen: the same number bounds the kernel call and
// decides who gets dropped mid-download, so picking it for one of those
// reasons silently sets the other - which is exactly what happened when it
// was 64 MiB for MAX_RW_COUNT's sake and quietly demanded 1.12 MB/s of every
// client. At the default 60 s this is 120,000 bytes.
inline constexpr size_t file_send_chunk(int send_timeout_s) {
  const size_t want =
      static_cast<size_t>(send_timeout_s > 0 ? send_timeout_s : 60) * kSlowClientRate;
  if (want < kFileSendChunkMin) return kFileSendChunkMin;
  if (want > kFileSendChunkMax) return kFileSendChunkMax;
  return want;
}

inline constexpr uint16_t kNoRoute = 0xffff;

class Http1 {
 public:
  // ONE of these per connection, so the order is by alignment and not by
  // topic: interleaving the flags with the pointers cost 34 bytes of
  // padding in 176, which is a cache line every five connections spent
  // on nothing. Widest first, the single-byte members last and together.
  struct Conn {
    // No RFC: octets received and not yet parsed. The name is this
    // server's; RFC 9112 2 has no word for a parser's leftover.
    std::string carry;
    size_t content_skip = 0;
    // RFC 9110 6.4: what a bound route's request body still owes -
    // the bytes themselves collect in `carry` behind the head, which
    // keeps the hand-off zero-copy. A konst route keeps skipping.
    size_t content_need = 0;
    // No RFC: a half-open span into the WIRE body of an asset (see
    // Assets::wire_iov), not into the file - a gzip member's octets are
    // not the stored ones.
    size_t asset_off = 0;
    size_t asset_end = 0;
    // A lent body splits the sink, so the segments around it carry offsets
    // the plan has to claim explicitly: `zc_covered` is how far it got.
    size_t zc_covered = 0;
    H2State* h2 = nullptr;
    const AssetEntry* asset = nullptr;
    WsConn* ws = nullptr;
    SseStream* sse = nullptr;
    const void* peer = nullptr;
    // NO RFC and NOT the kernel's: "zc" here is the [tune] knob's word,
    // zero_copy_threshold, and it means LENT INSTEAD OF COPIED - a dynamic
    // body frozen and rooted from the handler's return until the round it
    // belongs to has drained. It is NOT IORING_OP_SEND_ZC; this tree does
    // not use that opcode anywhere.
    mrb_state* zc_mrb = nullptr;
    mrb_value zc_value = {};
    // #30: every watcher this connection is running, keyed by the
    // watcher's own mrb_obj_id - nothing is invented to name them with.
    //
    // It is an mruby Hash and not a C++ map because these are Ruby
    // objects: a watcher nobody holds is collected, and with it the
    // source and block it keeps alive. ONE gc_register roots the hash
    // and the hash roots them all, instead of one registration each.
    //
    // The connection is the right owner because the watchers die with
    // it, and a completion arriving late for a connection already gone
    // is discarded by the generation guard every other op relies on -
    // `!c.live || c.gen != gen`. So nothing here counts anything, and
    // no removal has to be waited for.
    mrb_state* w_mrb = nullptr;
    mrb_value w_hash = {};
    // Added but not yet on the ring. Http1 cannot arm anything - it has
    // no ring - so it leaves the slot here and the reactor collects it,
    // the same way response.file leaves a path for arm_file_open.
    std::vector<int> w_pending;
    uint8_t listener = 0;
    uint8_t peer_len = 0;   // no RFC: the socket's address, already spelled
    bool fresh = true;
    bool packetized = false;
    bool zc_lent = false;   // a lend is outstanding right now
    bool zc_split = false;
    // response.file: the answer a run DEFERRED to the reactor. `want` = the
    // open is owed, `busy` = the ring is on it, `ready` = the head is
    // spelled and `more` may put it on the wire. Nothing else about the
    // request survives the run, so the framing it needs is copied here.
    //
    // Lazy, like h2/ws/sse below - most connections never call
    // response.file=, and this used to sit inline (10 std::strings plus a
    // dozen scalars) on EVERY connection slot, paid by the accept/recv/
    // send hot path whether or not it was ever touched. Allocated on first
    // use and kept for the life of the connection (not freed per request)
    // so a connection that repeatedly serves files doesn't thrash malloc;
    // `reset()` and `~Conn()` are the only places that delete it.
    // THREE sources meet in one struct, and the names say which is which.
    // The kernel's, by rule: pathname/buf/map_addr/map_length are the
    // ARGUMENTS they become (openat, io_uring_prep_read, munmap). HTTP's:
    // head, content_type, field_lines, content_length, content_sent,
    // status_code, if_modified_since, head_only, persist, minor. And the
    // access line's copies - the request they describe is gone by the time
    // the ring answers, so they are taken while it still exists.
    struct FileXfer {
      std::string pathname;      // openat(dirfd, pathname, flags)
      std::string head;          // RFC 9112 2.1: status-line + fields
      std::string content_type;  // RFC 9110 8.3
      std::string field_lines;   // RFC 9112 5: what the run added
      std::string buf;           // io_uring_prep_read(sqe, fd, buf, ...)
      std::string method_token;   // RFC 9110 9.1
      std::string request_target;  // RFC 9112 3.2
      std::string referer;         // RFC 9110 10.1.3
      std::string user_agent;      // RFC 9110 10.1.5
      size_t buf_filled = 0;  // how much of buf the read put there
      // RFC 9110 8.6: content_length is what Content-Length promised,
      // content_sent what has already gone out. The two being unequal is
      // the only thing that keeps a file alive across rounds.
      size_t content_length = 0;
      size_t content_sent = 0;
      // A mapped file: lent whole, in chunks no bigger than one send can
      // move. Like buf it deliberately survives file_clear() - the SQE
      // still points into it - and it goes back on the kDone round, which
      // is by construction the round AFTER the last lend.
      const char* map_addr = nullptr;  // munmap(addr, length)
      size_t map_length = 0;
      bool map_wanted = false;         // no RFC: above file_map_threshold
      int64_t if_modified_since = 0;   // RFC 9110 13.1.3
      uint16_t status_code = 0;        // RFC 9110 15
      uint8_t log_flags = 0;           // LogRec::flags, see kLogH2
      FileStage stage = FileStage::kNone;
      bool persist = true;             // RFC 9112 9.3
      bool head_only = false;          // RFC 9110 9.3.2
      bool if_modified_since_valid = false;
      int minor = 1;                   // RFC 9112 2.3: HTTP-version's
                                       // second DIGIT
    };
    FileXfer* file = nullptr;
    // Nothing is owed and nothing is held: the state a fresh connection and
    // a delivered file both stand in. The allocation itself survives - see
    // FileXfer's comment above.
    void file_clear() {
      if (file == nullptr) return;
      file->stage = FileStage::kNone;
      file->buf_filled = 0;
      // The counters end with the transfer they counted. Leaving them for
      // the next request is how a stale content_length gets read as this
      // one's.
      file->content_length = 0;
      file->content_sent = 0;
      file->map_wanted = false;
      file->status_code = 0;
      file->log_flags = 0;
      file->pathname.clear();
      file->head.clear();
      file->content_type.clear();
      file->field_lines.clear();
      file->method_token.clear();
      file->request_target.clear();
      file->referer.clear();
      file->user_agent.clear();
    }
    // The address space goes back. Called from zc_release once the round
    // that borrowed the mapping has drained, and unconditionally when the
    // connection itself ends - a mapping nobody borrowed still has to go.
    void map_release() {
      if (file == nullptr || file->map_addr == nullptr) return;
      ::munmap(const_cast<char*>(file->map_addr), file->map_length);
      file->map_addr = nullptr;
      file->map_length = 0;
    }
    // The ONE end of the lend window - drained round, closed connection,
    // dead reactor. Never conditional on the round having succeeded.
    void zc_release() {
      // The mapping is NOT released from here. Which round may hand it back
      // is a decision, and decisions live in file_step(); this function
      // runs before that one and could only guess.
      // h2 lends PER STREAM and hands each one back where the stream ends,
      // but the last bytes are still in flight there - this is the point
      // that knows they are not, so the h2 backlog is freed from here.
      if (h2 != nullptr) h2->content_drain();
      zc_covered = 0;
      zc_split = false;
      if (!zc_lent) return;
      zc_lent = false;
      resource_body_unlend(zc_mrb, zc_value);
      zc_mrb = nullptr;
    }
    // #30: take one in. The slot is the watcher's one name - the key it
    // is filed under here and the field its completions carry back - so
    // there is nothing to translate between the ring and the hash.
    // Returns the slot, or -1 when this connection is already holding
    // as many as a tag can name.
    int watchers_add(mrb_state* mrb, mrb_value w) {
      if (w_mrb == nullptr) {
        w_hash = mrb_hash_new(mrb);
        mrb_gc_register(mrb, w_hash);
        w_mrb = mrb;
      }
      for (int i = 0; i < static_cast<int>(kMaxWatchers); i++) {
        if (!mrb_nil_p(mrb_hash_get(mrb, w_hash, mrb_int_value(mrb, i)))) continue;
        watcher_set_slot(w, i);
        mrb_hash_set(mrb, w_hash, mrb_int_value(mrb, i), w);
        w_pending.push_back(i);
        return i;
      }
      return -1;
    }

    mrb_value watchers_at(int slot) const {
      if (w_mrb == nullptr) return mrb_nil_value();
      return mrb_hash_get(w_mrb, w_hash, mrb_int_value(w_mrb, slot));
    }

    // Gone for good: cancelled by the caller, then emptied here, so the
    // sweep that comes later finds nothing to free and nothing to cancel
    // a second time.
    void watchers_drop(int slot) {
      if (w_mrb == nullptr) return;
      const mrb_value w = watchers_at(slot);
      if (mrb_nil_p(w)) return;
      watcher_disarm(w);
      mrb_hash_delete_key(w_mrb, w_hash, mrb_int_value(w_mrb, slot));
    }

    // #30: let the watchers go. Unrooting the hash is the whole of it -
    // the watchers become collectable, and each one's CDATA destructor
    // is what finally takes its descriptor out of the ring.
    void watchers_release() {
      w_pending.clear();
      if (w_mrb == nullptr) return;
      mrb_gc_unregister(w_mrb, w_hash);
      w_mrb = nullptr;
      w_hash = mrb_nil_value();
    }
    // The Ring resets this; `li` is the App's key to "whose connection is
    // this", `pkt` says whether that listener is TCP.
    void reset(uint8_t li, bool pkt) {
      zc_release();
      watchers_release();
      map_release();
      delete file;
      file = nullptr;
      peer_len = 0;
      carry.clear();
      content_skip = 0;
      content_need = 0;
      listener = li;
      packetized = pkt;
      fresh = true;
      h2_free(h2);
      h2 = nullptr;
      ws_free(ws);
      ws = nullptr;
      sse_free(sse);
      sse = nullptr;
      asset = nullptr;
      asset_off = 0;
      asset_end = 0;
    }
    // The websocket, the stream, the h2 state and a response.file transfer
    // die with the connection.
    ~Conn() {
      zc_release();
      map_release();
      delete file;
      h2_free(h2);
      ws_free(ws);
      sse_free(sse);
    }
  };

  struct AppInput {
    const RouteTable* table = nullptr;
    const Resource* const* resources = nullptr;
    size_t nroutes = 0;
    const RouteTable* ws_table = nullptr;
    const WsResource* const* ws_resources = nullptr;
    size_t ws_nroutes = 0;
    const RouteTable* sse_table = nullptr;
    const SseResource* const* sse_resources = nullptr;
    size_t sse_nroutes = 0;
  };

  Http1(const AppInput* apps, size_t napps, Assets* assets = nullptr);
  Http1(const RouteTable& table, const Resource* const* resources, size_t nroutes,
        Assets* assets = nullptr);

  // #210: the error pages render in a VM, and this layer is handed one
  // rather than owning it - the h1 model (#173) is bytes in, bytes out,
  // and a caller that never calls this gets the bodyless statuses it
  // always got.
  bool open_error_assets(mrb_state* mrb, Assets* error_assets, char* err, size_t errlen);

  void on_tick();

  bool pending(const Conn& st) const;

  // WHATWG HTML: does this connection carry a source with its own schedule?
  bool timed(const Conn& st) const { return st.sse != nullptr; }

  // NO RFC - this becomes a struct msghdr, so it carries that struct's
  // names: the segments are its msg_iov, their count its msg_iovlen, and
  // each segment is an iovec. take_plan resolves them one to one.
  //
  // Two fields are NOT part of the ABI and say so. `off` is what makes a
  // segment resolvable at all: a sink segment cannot know its address
  // until the sink has stopped growing, so it carries an offset and gets
  // its iov_base at the last moment. And `byte_total` is the SUM of the
  // iov_lens, which is what a round is measured against - it used to be
  // called iov_len too, one name for a segment's length and for every
  // segment's length together.
  struct Plan {
    struct Seg {
      const char* iov_base;
      size_t off;  // not ABI: where in the sink, when iov_base is null
      size_t iov_len;
    };
    // Not ABI: our own bound on how many segments one round may carry.
    static constexpr unsigned kSegs = 1023;
    Seg iov[kSegs];
    unsigned iovlen = 0;
    size_t byte_total = 0;
    size_t byte_cap = 0;
  };

  bool feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan);

  bool more(Conn& st, std::string& sink, Plan& plan);

  // response.file, the reactor's half. A bound run may name a file instead
  // of spelling a body; opening it is disk work, so it never happens inside
  // the run. These five are the whole contract with the Ring - it drives
  // openat2/statx/read through the ring and hands each result back here,
  // and the answer reaches the wire through `more` like every other
  // continuation. Any refusal - a miss, a directory, a resolve flag
  // catching an escape - lands as the SAME 404 file_reject spells.
  const char* file_take(Conn& st);
  void file_reject(Conn& st);
  void file_error(Conn& st, const char* why);
  bool file_stat(Conn& st, const struct statx& stx, size_t* want);
  char* file_buffer(Conn& st, size_t n);
  void file_ready_now(Conn& st, size_t n);
  void file_mapped(Conn& st, const char* p, size_t n);
  // Is a round waiting for `more` to run? kDone counts: it puts nothing on
  // the wire, but it is the round that hands the mapping back and writes
  // the access line, so nothing may go idle in front of it.
  static bool file_answerable(const Conn& st) {
    return st.file != nullptr &&
           (st.file->stage == FileStage::kDeliver || st.file->stage == FileStage::kDone);
  }
  // 0 = do not map; otherwise the exact length to map. ONE question, ONE
  // answer - the split that made the read path ask "map?" and then use the
  // map's length to read with.
  static size_t file_map_len(const Conn& st) {
    return (st.file != nullptr && st.file->map_wanted) ? st.file->content_length : 0;
  }
  // Which shape a resource's answer takes. The five were four `if`s that
  // each decided AND wrote, with `answered` as a shadow flag set in three
  // places - and an access line below that recomputed the byte count for
  // itself, so it could disagree with what actually went out.
  struct AnswerStep {
    enum class Shape : uint8_t {
      kAlready,    // the dynamic-head branch already spelled it
      kLent,       // a lent body behind the 200 prefix
      kGzip,       // conneg between identity and gzip
      kPlain,      // a copied body behind the 200 prefix
      kException,  // a 500 the resource spelled itself (may demote)
      kStatus      // a prebuilt status line and nothing else
    };
    Shape shape = Shape::kStatus;
    size_t body_len = 0;  // what the access line counts
    bool answered = false;
  };
  static AnswerStep answer_step(uint16_t status, bool answered_already, bool have_body,
                                size_t body_len, size_t lent_len, bool has_lent,
                                bool gzip_ok, bool bound) {
    AnswerStep s;
    s.body_len = has_lent ? lent_len : body_len;
    s.answered = answered_already;
    if (have_body && status == 200) {
      s.shape = has_lent ? AnswerStep::Shape::kLent
                         : (gzip_ok ? AnswerStep::Shape::kGzip : AnswerStep::Shape::kPlain);
      s.answered = true;
    } else if (answered_already) {
      s.shape = AnswerStep::Shape::kAlready;
    } else if (status == 500 && bound) {
      // Whether a body exists is a question for the VM, so the caller
      // demotes this to kStatus when the answer is no.
      s.shape = AnswerStep::Shape::kException;
    } else {
      s.shape = AnswerStep::Shape::kStatus;
    }
    return s;
  }

  // RFC 9113 6.9.1: what ONE stream may put on the wire this round. Both
  // windows, what is left of the body, and - for a copied buffer only -
  // the delivery chunk. This was the same twenty lines three times over,
  // once per source, each computing the budget again and each writing in
  // the middle of the arithmetic.
  // How many bytes of THE stream's body go out this round. It no longer
  // picks among sources - there is one - so it decides a count and nothing
  // else; where the bytes come from is H2Stream::Body's business.
  struct H2SendStep {
    size_t start = 0;   // first byte of the body this round frames
    size_t give = 0;    // how many bytes it may frame
    size_t total = 0;   // the body's length, so END_STREAM is a comparison
    bool ends = false;  // give reaches the last byte
  };
  static H2SendStep h2_send_step(const H2Stream& s, int64_t conn_window, size_t chunk) {
    H2SendStep o;
    if (!s.response_content.owes()) return o;
    o.start = s.response_content.sent;
    o.total = s.response_content.length;
    size_t remaining = s.response_content.length - s.response_content.sent;
    // A copied buffer is bounded per round; a lend and a mapping are not.
    if (s.response_content.src == H2Stream::Content::Src::kOwned && remaining > chunk) {
      remaining = chunk;
    }
    const int64_t budget = conn_window < s.flow_window ? conn_window : s.flow_window;
    if (budget <= 0) return o;  // owed, but the window is shut: give stays 0
    o.give = remaining;
    if (static_cast<int64_t>(o.give) > budget) o.give = static_cast<size_t>(budget);
    o.ends = o.give != 0 && o.start + o.give == o.total;
    return o;
  }

  // What the asset tier does with ONE request, computed here and performed
  // by the caller - the range verdict used to be decided inside the branch
  // that was already writing, with two shadow variables (alog_st/alog_by)
  // carrying the answer back out.
  //   status_code      RFC 9110 15 - and what the access line says
  //   first_byte_pos   RFC 9110 14.1.2
  //   content_length   RFC 9110 8.6 - the span sent, and what the access
  //                    line counts
  //   sends_content    RFC 9110 6.4
  //   copy_content     no RFC: small enough to ride the sink instead of
  //                    being lent out of the mapping
  struct AssetStep {
    // Which of the four heads this request gets; the enum is HeadKind, not
    // Head, because AssetEntry::Head is a head - this only picks one.
    enum class HeadKind : uint8_t { kRefusal, kNormal, kRange, kUnsatisfiable };
    HeadKind head = HeadKind::kNormal;
    uint16_t status_code = 200;
    size_t first_byte_pos = 0;
    size_t content_length = 0;
    bool sends_content = false;
    bool copy_content = false;
  };
  // RFC 9110 14.1/14.2: a range is honoured only on a GET that would have
  // been a 200, and only when If-Range still matches the representation.
  static AssetStep asset_step(const AssetEntry& e, uint16_t verdict, bool head_only,
                              flow::Method m, const http::ReqValues& vals,
                              size_t warm_budget) {
    AssetStep s;
    s.status_code = verdict;
    if (verdict == 412 || verdict == 501) {
      s.head = AssetStep::HeadKind::kRefusal;
      return s;
    }
    const size_t complete_length = Assets::wire_len(e);
    if (verdict == 200 && !head_only && m == flow::Method::kGet && vals.range != nullptr &&
        (vals.if_range == nullptr ||
         http::if_range_matches(vals.if_range, vals.if_range_len, e.etag, sizeof(e.etag)))) {
      size_t first_byte_pos = 0, last_byte_pos = 0;
      switch (http::parse_range(vals.range, vals.range_len, complete_length, &first_byte_pos,
                                &last_byte_pos)) {
        case http::RangeParse::kOne:
          s.head = AssetStep::HeadKind::kRange;
          s.status_code = 206;
          s.first_byte_pos = first_byte_pos;
          s.content_length = last_byte_pos - first_byte_pos + 1;
          s.sends_content = true;
          break;
        case http::RangeParse::kUnsat:
          s.head = AssetStep::HeadKind::kUnsatisfiable;
          s.status_code = 416;
          return s;
        case http::RangeParse::kNone:
          break;
      }
    }
    if (s.head == AssetStep::HeadKind::kNormal && verdict == 200 && !head_only) {
      s.content_length = complete_length;
      s.sends_content = true;
    }
    s.copy_content = s.sends_content && s.content_length <= warm_budget;
    return s;
  }

  // The next round of a transfer, computed and not performed.
  //
  // Defined HERE, not in a .cpp: `more` lives in another translation unit
  // and this build has no LTO, so a definition over there would be a real
  // call with a 48-byte return through memory (SysV returns anything past
  // 16 bytes that way). Inlined, the FileStep never exists - the compiler
  // keeps its fields in registers. Purity only pays where the compiler can
  // SEE it.
  static FileStep file_step(const Conn::FileXfer& x, size_t chunk) {
    FileStep s;
    s.persist = x.persist;
    s.sent_after = x.content_sent;
    s.next = x.stage;
    switch (x.stage) {
      case FileStage::kDeliver: {
        const bool mapped = x.map_addr != nullptr;
        const size_t left =
            x.content_length > x.content_sent ? x.content_length - x.content_sent : 0;
        // A mapping lends a bounded chunk of itself; a window lends exactly
        // what the read put in it.
        const size_t take = mapped ? (left < chunk ? left : chunk) : x.buf_filled;
        s.head = !x.head.empty();
        if (take != 0) {
          s.src = mapped ? FileStep::Src::kMapping : FileStep::Src::kWindow;
          // A mapping is walked from where the transfer stands; the window
          // buffer holds only this round's bytes and starts at zero.
          s.start = mapped ? x.content_sent : 0;
        }
        s.give = take;
        s.sent_after = x.content_sent + take;
        // A window is refilled by the ring, so the next round waits on it.
        // A mapping has no read coming to wake it and drives itself.
        s.next = s.sent_after < x.content_length
                     ? (mapped ? FileStage::kDeliver : FileStage::kRing)
                     : FileStage::kDone;
        break;
      }
      case FileStage::kDone:
        // The last lend has DRAINED - that is what kDone means and the only
        // way to reach it. So this is where the mapping goes back and where
        // the transfer's one access line is owed.
        s.release_map = x.map_addr != nullptr;
        s.log = true;
        s.clear = true;
        s.next = FileStage::kNone;
        break;
      default:
        break;
    }
    return s;
  }
  // The ONE place a transfer's state changes as a round is delivered.
  void file_apply(Conn& st, const FileStep& step);
  // The single access line of a transfer, with the bytes that really went
  // out. Called on the kDone round, or by file_abandon when a connection
  // dies under one; the stage is what keeps it from happening twice.
  void file_log(Conn& st);
  // A connection closing under a transfer still owes its access line.
  void file_abandon(Conn& st);
  // Nothing owed, nothing on the wire: give the read buffer back, or a slot
  // that once served a big file would hold those bytes for the process's
  // life. The Ring calls this only where BOTH are true.
  static void file_release(Conn& st) {
    if (st.file != nullptr && st.file->buf.capacity() > kDeliverChunk) {
      std::string().swap(st.file->buf);
    }
  }

  // The App FORMATS lines; the Ring flushes the buffer. Opt-in.
  Logger* access_log() { return &alog_; }
  // The only way an access line is ever built.
  void enable_access_log() { alog_.enabled = true; }
  // The second stream: its own socket, its own daemon, its own file.
  Logger* error_log() { return &elog_; }
  // The only way an error record is ever built.
  void enable_error_log() { elog_.enabled = true; }
  // [tune] zero_copy_threshold, once, before the first accept.
  void set_zero_copy_threshold(size_t n) { zc_min_ = n; }

  // [tune] file_map_threshold, once, before the first accept. 0 = never map.
  void set_file_map_threshold(size_t n) { map_min_ = n; }
  // The Ring owns the send clock, so the Ring is what tells this layer how
  // much one send may carry - one rule, one place.
  void set_send_timeout(int secs) { send_chunk_ = file_send_chunk(secs); }

  // The Ring asks before it opens: the size that decides this is the App's
  // to weigh, because the App is what holds the operator's answer.


 private:
  struct AppSlot;

  // RFC 6455 4.1: what a websocket upgrade needs to know about the request
  // that asked for it. One argument instead of eleven - see #std-first: the
  // arguments that always travel together are a thing without a name, and
  // this is that thing. Every member is a view or a reference into bytes
  // the caller owns for the length of the call.
  // WHATWG HTML: what an event-stream route needs to know about the request
  // that asked. Same reason as WsUpgrade below - see #std-first.
  struct SseBegin {
    const AppSlot& slot;
    int route;
    std::string_view method;
    std::string_view path;
    const RouteSpans& spans;
    const void* hdrs;   // struct phr_header[]; the framer's header is not here
    size_t nhdr;
    int minor;
    flow::Method m;
    const http::ReqValues& vals;
    uint8_t lflags;
  };

  struct WsUpgrade {
    const AppSlot& slot;
    int route;
    std::string_view path;
    const RouteSpans& spans;
    std::string_view key;
    const void* hdrs;   // struct phr_header[]; the framer's header is not here
    size_t nhdr;
    const http::ReqValues& vals;
    std::string_view rest;  // bytes after the head, already in hand
  };

  struct Resp {
    std::string bytes;
    size_t date_off = 0;
  };
  struct Variants {
    Resp plain, keep, close;
  };
  struct H2Block {
    std::string bytes;
  };

  // #210: where an error answer's own HPACK block and its rendered page
  // are built. Both outlive the framing, because a body the window cannot
  // finish is copied onto the stream from here.
  struct H2ErrorPage {
    H2Block block;
    std::string rendered;
  };

  // What one h2 answer puts on the wire: the HPACK block that heads it and
  // the body bytes that follow.
  struct H2Answer {
    const char* body = nullptr;
    size_t blen = 0;
    const H2Block* blk = nullptr;
  };

  struct Bundle;

  // And what spelling an ERROR answer needs to know first: the status it
  // carries, the words #210 filled in for it, the header values the request
  // frame still holds (for Accept), and the route whose Allow a 405 keeps.
  struct H2ErrorAsk {
    uint16_t status;
    const ErrorPages::Fields& fields;
    const http::ReqValues* vals;
    const Bundle* bundle;
  };

  struct Bundle {
    flow::KonstSet konst;
    // RFC 9110 12.5.1: what c4 weighs an Accept against - the media type
    // WITHOUT the charset parameter konst.content_type grows here, and
    // present even for the default route, which has no Resource behind it.
    std::string accept_type;
    const Resource* res = nullptr;
    std::array<uint16_t, 600> index {};
    bool dynamic_body = false;
    bool bound = false;
    bool gzip_ok = false;
    Variants ok_head;
    Variants ok_prefix;
    Variants ok_prefix_vary;
    Variants ok_prefix_gzip;
    Variants err_prefix;
    H2Block h2_err;
    std::string h2_data200;
  };

  void build(const AppInput* apps, size_t napps);
  static void build_variants(Variants& v, uint16_t status, const char* extra,
                             const char* body, const char* date);
  static void build_one_variant(Resp& r, uint16_t status, const char* extra, const char* body,
                                const char* date, const char* conn);
  static void assign_without_tail(const Resp& src, Resp& dst, size_t cut);
  static void build_open_prefix(Resp& r, const char* status_line, const char* conn,
                                const std::string& extra, const char* enc);
  // RFC 9113 6.2: one whole HEADERS frame for the cache to replay - the
  // route's prebuilt block, the per-answer fields, and the date.
  struct CachedHead {
    const H2Block& block;
    std::span<const unsigned char> fields;
    std::span<const unsigned char> date;
  };
  static void cache_headers(std::string& out, const CachedHead& head);
  // WHATWG HTML: an event stream's one access record. SseLine is what the
  // seven arguments were - see #std-first.
  struct SseLine {
    std::string_view method;
    std::string_view path;
    const http::ReqValues& vals;
    uint16_t status;
    uint8_t lflags;
  };
  static void log_sse(Logger& lg, const Conn& st, const SseLine& line);
  void build_status(uint16_t status, const char* extra, const char* body);
  void stock_status(bool have[600], uint16_t s);
  void build_bundle(Bundle& b, const Resource* res);
  static void patch_date(Variants& v, const char* core);
  static void assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                       bool head_only);
  bool feed_parse(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan);
  static void claim_sink(Conn& st, const std::string& sink, Plan& plan);
  static void lend_body(Conn& st, std::string& sink, const char* body, size_t len, Plan& plan);
  // RFC 9110 12.5.3/12.5.5: what a dynamic 200 chooses between - the two
  // prebuilt prefixes, whether gzip is on the table at all (the peer
  // accepts it AND this connection is packetized), and whether the request
  // wants the body behind the head.
  struct DynamicBody {
    const Resp& prefix_id;
    const Resp& prefix_gz;
    bool may_gzip;
    bool head_only;
  };
  void assemble_dynamic(const DynamicBody& d, std::string& sink);
  // RFC 9112 9.3: one prebuilt status in its three connection spellings.
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];
  }
  // The same status without its Content-Length and terminator: what an
  // error answer that HAS a page puts its own two fields behind.
  const Variants& prefixes(uint16_t status) const {
    return store_prefix_[index_[status]];
  }
  // RFC 9110 15: the error answer this connection gets - the prebuilt
  // status line and Date, then the page rendered for THIS request. When
  // there is no page (no VM handed over, or a template that raised) the
  // bodyless status goes out instead, which is what this server sent
  // before there were pages at all.
  // The parts of one: the prefix its status line and Date come from, the
  // bodyless spelling that stands when there is no page, the status, the
  // media the page renders in, the words #210 filled in, and whether the
  // request wants the body behind the head.
  struct ErrorAnswer {
    const Resp& prefix;
    const Resp& bodyless;
    uint16_t status;
    int media;
    const ErrorPages::Fields& fields;
    bool head_only;
  };
  void spell_error(const ErrorAnswer& e, std::string& sink);
  // What one request round already knows by the time the head is parsed.
  // A step that leaves the straight line takes this instead of twenty
  // arguments - which is what made those steps stay inline before.
  struct Round {
    Conn& st;
    const Bundle* b;
    const char* view;
    size_t viewlen;
    size_t off;
    size_t head_len;
    bool in_place;
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor;
    bool persist;
    bool head_only;
    size_t content_length;
    uint8_t lflags;
    const flow::ReqFacts& facts;
    const http::ReqValues& vals;
  };

  // What a step that may take the round over answers with.
  enum class Took : uint8_t {
    kNo,           // not this step's request; the straight line continues
    kNextRequest,  // answered, and the pipeline may hold another
    kOwed,         // answered so far as it can be; bytes are still owed
    kClose         // answered, and the connection ends
  };

  // RFC 9110 6.3: response.file named a file, so no body is spelled here
  // - the framing goes onto the connection and the reactor drives
  // openat2/statx/read. Answers whether it took the round.
  bool answer_from_file(Round& r, uint16_t status);

  // RFC 9110 6.3 / RFC 9111: a mounted archive answers this target, head
  // and body, without the flow or the VM. /error_assets/ resolves against
  // the error archive, everything else against --assets.
  Took answer_from_assets(Round& r, std::string& sink, Plan* plan);

  bool fail(Conn& st, uint16_t status, std::string& sink, uint8_t log_flags = 0);
  // response.file's answer, head only - the bytes ride after it as a lent
  // segment. `prebuilt` takes the status straight out of the shared store.
  void file_spell(Conn& st, uint16_t status_code, size_t content_length, bool bodyless);
  void file_prebuilt(Conn& st, uint16_t status_code);
  bool ws_upgrade(Conn& st, const WsUpgrade& up, std::string& sink);

  bool sse_begin(Conn& st, const SseBegin& req, std::string& sink);

  void h2_build_block(H2Block& b, uint16_t status, const std::string* ctype,
                      const std::string* allow);
  bool h2_error_page(const H2ErrorAsk& ask, H2ErrorPage& page, H2Answer& out);

  bool h2_begin(Conn& st, std::string& sink);
  bool h2_feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan);
  bool h2_error(Conn& st, uint32_t code, std::string& sink);
  void h2_rst(Conn& st, uint32_t stream_id, uint32_t code, std::string& sink);
  // RFC 9110 15.6.1: response.file has no HTTP/2 path yet - a run that
  // named one is refused rather than served the empty body it never meant
  // to send. Its own function because those fifteen lines are not part of
  // answering a stream, and inline they cost h2_answer 952 bytes.
  uint16_t h2_refuse_file(Conn& st, const ReqView* req);
  bool h2_dispatch(Conn& st, uint32_t stream_id, bool end_stream, const unsigned char* blk,
                   size_t blk_len, std::string& sink);
  const ReqView* h2_parked_view(Conn& st, const std::string& target, ReqView& out);
  void h2_log(Conn& st, const flow::ReqFacts& facts, const char* target, size_t tlen);
  // `target` rides beside `req` because an error answer needs it even
  // when no route matched - a 404 names what was not found, and that is
  // exactly the case where there is no ReqView (#210).
  // RFC 9113 8.1: one stream's request, as much of it as answering needs.
  // Eight arguments travelled together - see #std-first.
  struct H2Request {
    uint32_t stream_id;
    const flow::ReqFacts& facts;
    const http::ReqValues* vals;
    const ReqView* req;
    std::string_view target;
    uint16_t route;
    bool head_only;
  };
  bool h2_answer(Conn& st, const H2Request& q, std::string& sink);
  void h2_flush_pending(Conn& st, std::string& sink, Plan* plan);
  void h2_build_asset_blocks(AssetEntry& e);
  void h2_build_asset_shared();
  // RFC 9113 6.1/6.9: one asset answer on one stream - the stream it goes
  // out on, the entry it comes from, the status it carries, whether the
  // request wants the body behind the head, and the half-open window of
  // the wire body this answer covers.
  struct H2Asset {
    uint32_t stream_id;
    const AssetEntry& entry;
    uint16_t status;
    bool head_only;
    size_t win_off;
    size_t win_end;
  };
  bool h2_asset_answer(Conn& st, const H2Asset& a, std::string& sink);

  struct AppSlot {
    const RouteTable* table = nullptr;
    uint16_t base = 0;
    uint16_t count = 0;
    const RouteTable* ws_table = nullptr;
    uint16_t ws_base = 0;
    const RouteTable* sse_table = nullptr;
    uint16_t sse_base = 0;
  };

  time_t sec_ = 0;
  std::vector<AppSlot> apps_;
  std::vector<Bundle> bundles_;
  std::vector<const WsResource*> ws_res_;
  std::vector<const SseResource*> sse_res_;
  std::vector<Variants> store_;
  std::vector<Variants> store_prefix_;
  std::array<uint16_t, 600> index_ {};
  ErrorPages err_pages_;
  // Not the operator's --assets: the pictures an error page names, under
  // their own reserved prefix, mounted whether or not anything else is.
  Assets* error_assets_ = nullptr;
  std::vector<H2Block> h2_store_;
  H2Block h2_asset405_;
  H2Block h2_asset406_;
  Assets* assets_ = nullptr;
  size_t warm_budget_ = kWarmBudgetDefault;
  size_t zc_min_ = kZeroCopyDefault;
  size_t map_min_ = kFileMapDefault;
  size_t send_chunk_ = file_send_chunk(60);
  Logger alog_;
  Logger elog_;
  uint16_t alog_status_ = 0;
  size_t alog_bytes_ = 0;
  std::string body_;
  std::string gz_body_;
  // RFC 9110 6.3: the field lines one bound run produced (resource_run
  // fills it); empty keeps every prebuilt path byte-identical.
  std::string rhdrs_;
  char date_[29] = {};
};
}

namespace webmachine {
// NO SPECIFICATION, and that is the entry. Nothing below is HTTP and
// nothing is the kernel's - these are OPERATING decisions, and the only
// source that names them is the surface an operator types at: the TOML
// keys, the CLI flags, and the conf.* setters an app writes. So those are
// the names, verbatim, all the way down - a knob spelled header_timeout
// in the file is header_timeout here too, and where a field says -1 it
// means "nobody said", because 0 is an answer an operator can give.
struct AppSpec {
  enum class Form : uint8_t { kNone, kPort, kUnix, kUrl };
  Form form = Form::kNone;
  int port = 0;
  std::string unix_path;
  std::string url_host;
  std::string bound_url;
  bool bound = false;
  RouteTable table;
  std::vector<std::unique_ptr<Resource>> resources;
  RouteTable ws_table;
  std::vector<std::unique_ptr<WsResource, void (*)(WsResource*)>> ws_resources;
  RouteTable sse_table;
  std::vector<std::unique_ptr<SseResource, void (*)(SseResource*)>> sse_resources;
  mrb_value ready = mrb_nil_value();
  bool have_ready = false;
  bool registered = false;
  // conf.disable_http_cats = true; -1 = this app said nothing. The pack
  // is one mount for the process, so the first app with an opinion is the
  // one it follows - the same order every other conf answer here takes.
  int8_t disable_http_cats = -1;
  // conf.zero_copy_threshold = N; -1 = this app said nothing.
  long long zero_copy_threshold = -1;
  // conf.file_map_threshold = N; -1 = this app said nothing.
  long long file_map_threshold = -1;
  // conf.docroot = PATH; empty = this app said nothing. --docroot and
  // [server] docroot both beat it, same order as every other choice here.
  std::string docroot;
  // conf.certificate = PATH, conf.private_key = PATH, and whether
  // conf.url said https. All three have to agree, and server.cpp is
  // where that is checked - a listener either serves TLS or does not.
  std::string cert_path;
  std::string key_path;
  bool tls = false;
};

void application_init(mrb_state* mrb, struct RClass* wm);

bool app_load(mrb_state* mrb, const char* path, char* err, size_t errlen);

bool app_registered_all(std::vector<AppSpec*>& out, size_t max_listeners, char* err,
                        size_t errlen);

AppSpec* app_assets_only();

void app_mark_bound(AppSpec& spec, const char* unix_path, int port);

bool app_ready_run(mrb_state* mrb, AppSpec& spec, char* err, size_t errlen);
}

namespace webmachine {
// server.docroot: the ONE directory response.file may reach, resolved to a
// canonical absolute path and opened O_DIRECTORY|O_PATH once at startup. That
// fd is what RESOLVE_BENEATH anchors against - the kernel does the
// confinement, this code never does path math of its own.
bool docroot_open(const char* path, char* err, size_t errlen);

// Did an operator configure one? response.file= refuses by name when not.
bool docroot_ready();

// The dirfd every per-request openat2 resolves relative to; -1 when unset.
int docroot_fd();

// The canonical absolute path, for the refusals that have to name it.
const char* docroot_path();

// The open_how every response.file open uses - built once, never per request.
const struct open_how* docroot_how();

// What main() resolved: the CLI flags and the [server]/[log]/[tune]
// sections, merged, with the CLI winning. cli_* keeps its prefix on
// purpose - it is the reason those two beat the file.
struct ServerOptions {
  const char* assets_path = nullptr;
  // #210: the file an error answer may hand over - the shipped one by
  // default, or the operator's, in which case whatever they put in it is
  // what response.error_asset can name.
  const char* error_assets_path = nullptr;
  const char* docroot_path = nullptr;
  const char* mime_types_path = nullptr;
  const char* log_path = nullptr;
  const char* log_privacy = nullptr;
  const char* error_log_path = nullptr;
  unsigned long long log_max_bytes = 500ull * 1024 * 1024;
  int stop_fd = -1;
  const char* cli_unix = nullptr;
  int cli_port = 0;
  const char* app_path = nullptr;
  unsigned sq_entries = 0;
  int backlog = 0;
  int header_timeout = 0;
  int send_timeout = 0;
  int idle_timeout = 0;
  // -1 = nobody said; 0 = said "never lend". See kZeroCopyDefault.
  long long zero_copy_threshold = -1;
  // -1 = nobody said; 0 = said "never map". See kFileMapDefault.
  long long file_map_threshold = -1;
};
void server_options(const ServerOptions& opts);

bool server_backend_ok(char* err, size_t errlen);

void server_init(mrb_state* mrb, struct RClass* wm);

int server_run(mrb_state* mrb, char* err, size_t errlen);

bool server_entered();
}

namespace webmachine {
// The TOML file as read, one member per key, grouped as the file groups
// them: [server], then [log], then [tune]. Nothing is defaulted here -
// absence has to stay visible, or --flag and conf.* cannot beat it.
struct Config {
  std::string path;

  std::string unix_path;
  int port = 0;
  std::string app;
  std::string assets;
  std::string docroot;
  std::string mime_types;
  std::string pidfile;

  std::string log_file;
  std::string log_privacy;
  std::string error_log_file;
  unsigned long long log_max_bytes = 0;

  int backlog = 0;
  unsigned sq_entries = 0;
  int header_timeout = 0;
  int send_timeout = 0;
  int idle_timeout = 0;
  // 0 is a CHOICE here ("never lend"), so absence is -1 and not 0.
  long long zero_copy_threshold = -1;
  // -1 = nobody said; 0 = said "never map". See kFileMapDefault.
  long long file_map_threshold = -1;
};

bool config_load(mrb_state* mrb, const char* path, Config& out, char* err, size_t errlen);
}

#define E_WM_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Error)))
#define E_WM_CONFIG_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(ConfigError)))
#define E_WM_ROUTE_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(RouteError)))

#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif

#define WM_LIKELY(x) __builtin_expect(!!(x), 1)
#define WM_UNLIKELY(x) __builtin_expect(!!(x), 0)


namespace webmachine {
inline constexpr uint32_t kMaxListeners = 16;
inline constexpr uint32_t kFdReserve = 128;
inline constexpr uint32_t kFixedTableKernelMax = 1u << 20;

// A ring's SQ/CQ pages are locked memory; failing to raise is not a
// reason not to start.
inline void raise_memlock() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return;
  if (rl.rlim_cur == rl.rlim_max) return;
  struct rlimit want {rl.rlim_max, rl.rlim_max};
  (void)::setrlimit(RLIMIT_MEMLOCK, &want);
}

// The one arithmetic with two consumers: the server sizes itself with it,
// webmachine-tune.sh only prints it.
inline uint32_t derive_max_conns(uint64_t nofile_limit, uint32_t extra_slots = 0) {
  const uint64_t taken = static_cast<uint64_t>(kFdReserve) + kMaxListeners + extra_slots;
  if (nofile_limit <= taken) return 0;
  uint64_t n = nofile_limit - taken;
  if (n + kMaxListeners + extra_slots > kFixedTableKernelMax) {
    n = kFixedTableKernelMax - kMaxListeners - extra_slots;
  }
  return static_cast<uint32_t>(n);
}

inline constexpr uint32_t kBufCount = 2048;
inline constexpr uint32_t kBufSize = 4096;
inline constexpr uint16_t kBufGroup = 0;
static_assert((kBufCount & (kBufCount - 1)) == 0, "buffer walk wraps by mask");
static_assert(static_cast<size_t>(kBufCount) <= SIZE_MAX / kBufSize,
              "pool size arithmetic must not overflow");

// Soft to hard, ceiling fs.nr_open, ONCE at init - the capacity falls out
// of whatever finally stands.
inline uint64_t raise_nofile() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
#ifdef IO_URING_FD_CEILING
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
  rlim_t target = rl.rlim_max;
  if (target == RLIM_INFINITY) {
    uint64_t nr_open = 1u << 20;
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

struct ListenerSpec {
  const char* unix_path = nullptr;
  int port = 0;
  // The PEM this listener answers with, already read - server.cpp owns
  // the bytes and outlives the ring. Both or neither: a listener with a
  // certificate is a TLS listener, and there is no other switch.
  const char* cert_pem = nullptr;
  size_t cert_len = 0;
  const char* key_pem = nullptr;
  size_t key_len = 0;
};

// What the reactor needs and nothing else - already resolved, already
// merged. Same names as the operator's knobs (see Config), so a value can
// be followed from the file to the SQE without changing what it is called.
struct RingConfig {
  ListenerSpec listeners[kMaxListeners] = {};
  uint32_t nlisteners = 0;
  int log_fd = -1;
  int err_fd = -1;
  unsigned sq_entries = 0;
  int backlog = 0;
  int header_timeout = 0;
  int send_timeout = 0;
  int idle_timeout = 0;
  int stop_fd = -1;
  // The VM to raise into when the reactor cannot go on. REQUIRED - init()
  // refuses without it, because the alternative is a library that ends
  // somebody else's process. See Ring::fatal.
  mrb_state* mrb = nullptr;
};

namespace detail {
enum : uint8_t {
  kAccept = 1, kRecv = 2, kSend = 3, kClose = 4, kSetup = 5, kStop = 6, kShutdown = 7,
  kMeminfo = 8, kLog = 9, kPeer = 10,
  // response.file: one kind per stage, so the tag needs no second field.
  kFileOpen = 11, kFileStat = 12, kFileRead = 13, kFileClose = 14,
  // #30: a watcher firing. This one DOES need a second field - a
  // connection may run several - and bits 48..55 of the tag were never
  // spoken for, so the slot goes there and the layout is unchanged.
  kWatch = 15,
  // The handover, one kind per setsockopt so a failing CQE says which:
  // TCP_ULP first, then the two crypto_info blobs.
  kTlsUlp = 16, kTlsTx = 17, kTlsRx = 18,
  // close_notify on the way out; nothing waits for it, the tag only
  // keeps its completion from being read as some other slot's.
  kTlsBye = 19,
  // A send key turned before its record limit. The completion matters:
  // nothing more may go out under the old key.
  kTlsTxKey = 20
};


// user_data: kind(8) | gen(16) | idx(32); gen guards a reused slot.
inline uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
}
// #30: which watcher, on top of which connection - 8 bits of the tag,
// so kMaxWatchers of them (declared further up, where Conn needs it).
inline uint64_t watch_tag(uint16_t gen, uint32_t idx, uint8_t slot) {
  return tag(kWatch, gen, idx) | (static_cast<uint64_t>(slot) << 48);
}
inline uint8_t watch_slot(uint64_t ud) { return static_cast<uint8_t>(ud >> 48); }

enum : uint32_t { kStSocket = 1, kStSockopt = 2, kStBind = 3, kStListen = 4, kStName = 5 };

// Which stage of the setup chain a failing CQE belongs to.
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
}

template <class App>
class Ring {
 public:
  // One reactor, one io backend, no globals.
  explicit Ring(App& app) : app_(app) {}
  Ring(const Ring&) = delete;
  Ring& operator=(const Ring&) = delete;

  // The ring exit is what ends surviving connections, and what unlinks a
  // unix listener's path.
  ~Ring() {
    for (ktls_keys*& k : tls_keys_) {
      ktls_keys_free(k);
      k = nullptr;
    }
    if (ring_up_) {
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

  // Everything through the ring: unlink, socket_direct, setsockopt, bind,
  // listen as ONE linked chain, every CQE checked, a failure naming its stage.
  bool init(const RingConfig& cfg, char* err, size_t errlen) {
    mrb_ = cfg.mrb;
    if (mrb_ == nullptr) {
      std::snprintf(err, errlen, "RingConfig::mrb is required - the reactor raises rather "
                                 "than ending a process it does not own");
      return false;
    }
    int rc = 0;
    raise_memlock();
    constexpr unsigned kSqWanted = 32768;
    constexpr unsigned kSqFloor = 1024;
    constexpr unsigned kSetupFlags =
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    const unsigned sq_wanted = cfg.sq_entries != 0 ? cfg.sq_entries : kSqWanted;
    const unsigned sq_floor = sq_wanted < kSqFloor ? sq_wanted : kSqFloor;
    struct io_uring_params p {};
    for (sq_entries_ = sq_wanted;; sq_entries_ /= 2) {
      p = io_uring_params{};
      p.flags = kSetupFlags;
      rc = io_uring_queue_init_params(sq_entries_, &ring_, &p);
      if (rc == 0) {
        sq_entries_ = p.sq_entries;
        break;
      }
      if (sq_entries_ <= sq_floor) {
        std::snprintf(err, errlen, "io_uring_queue_init(%u): %s", sq_entries_,
                      std::strerror(-rc));
        return false;
      }
    }
    io_uring_register_ring_fd(&ring_);
    ring_up_ = true;

    const uint64_t nofile = raise_nofile();
    log_fd_ = cfg.log_fd;
    err_fd_ = cfg.err_fd;
    backlog_ = cfg.backlog != 0 ? cfg.backlog : 511;
    header_timeout_ = cfg.header_timeout != 0 ? cfg.header_timeout : 60;
    send_timeout_ = cfg.send_timeout != 0 ? cfg.send_timeout : 60;
    idle_timeout_ = cfg.idle_timeout != 0 ? cfg.idle_timeout : 75;
    app_.set_send_timeout(send_timeout_);
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
    rc = io_uring_register_file_alloc_range(&ring_, 0, max_conns_);
    if (rc != 0) {
      std::snprintf(err, errlen, "register_file_alloc_range: %s", std::strerror(-rc));
      return false;
    }

    const size_t pool_bytes = static_cast<size_t>(kBufCount) * kBufSize;
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
    const int mask = io_uring_buf_ring_mask(kBufCount);
    for (uint32_t i = 0; i < kBufCount; i++) {
      io_uring_buf_ring_add(buf_ring_, pool_ + static_cast<size_t>(i) * kBufSize, kBufSize,
                            static_cast<uint16_t>(i), mask, static_cast<int>(i));
    }
    io_uring_buf_ring_advance(buf_ring_, kBufCount);

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
      if (!setup_listener_keys(li, cfg.listeners[li], err, errlen)) return false;
    }
    nlisteners_ = cfg.nlisteners;

    conns_.resize(max_conns_);
    live_bits_.assign((static_cast<size_t>(max_conns_) + 63) / 64, 0);
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

  // Loop until the stop signal's completion lands.
  void run() {
    while (!stop_) tick(nullptr);
  }

  // ONE bounded step: the budget bounds the WORK, not just the wait, and
  // the batch is interrupted BETWEEN completions.
  bool tick(const struct __kernel_timespec* budget) {
    if (budget == nullptr) return step(nullptr, false);
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    int64_t deadline = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
    deadline += budget->tv_sec * 1000000000 + budget->tv_nsec;
    return step(&deadline, true);
  }

  // Readable exactly when this ring has completions to hand over.
  int fd() const { return ring_up_ ? ring_.ring_fd : -1; }

  // Did the stop signal's completion land?
  bool stopped() const { return stop_; }

  // Drain, then FORGET: the listeners close at once, and what survives the
  // grace is ended by the destructor's ring exit.
  void drain(int64_t grace_ns) {
    if (draining_) return;
    draining_ = true;
    close_listeners();
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    drain_deadline_ = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec + grace_ns;
    if (live_ == 0 || grace_ns <= 0) stop_ = true;
  }

  // How many accepted connections are still being served.
  uint32_t live_conns() const { return live_; }

  // The derived capacity - what this machine actually allows.
  uint32_t max_conns() const { return max_conns_; }

  // A TCP listener's REAL port, including the kernel's pick for port 0.
  int bound_port(uint32_t li) const { return li < kMaxListeners ? bound_port_[li] : 0; }

 private:
  // One listener as one linked chain; a stale unix path is unlinked OUTSIDE
  // the chain, because ENOENT there is normal.
  bool setup_listener(uint32_t li, const ListenerSpec& spec, char* err, size_t errlen) {
    const uint32_t slot = listener_base_ + li;
    const bool is_unix = spec.unix_path != nullptr;
    struct sockaddr_un sun {};
    struct sockaddr_in sin {};
    struct sockaddr* sa = nullptr;
    socklen_t salen = 0;
    if (is_unix) {
      sun.sun_family = AF_UNIX;
      const size_t payload_length = std::strlen(spec.unix_path);
      if (payload_length >= sizeof(sun.sun_path)) {
        std::snprintf(err, errlen, "listener %u: unix path too long (%zu)", li, payload_length);
        return false;
      }
      std::memcpy(sun.sun_path, spec.unix_path, payload_length + 1);
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
        if (cqe->res < 0 && cqe->res != -ENOENT) {
          std::snprintf(err, errlen, "unlink %s: %s", spec.unix_path, std::strerror(-cqe->res));
          return false;
        }
        io_uring_cqe_seen(&ring_, cqe);
      }
    } else {
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

    static const int kOne = 1;
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
    if (is_unix) unix_paths_.emplace_back(spec.unix_path);
    unix_listener_[li] = is_unix;

    if (!is_unix) {
      bound_port_[li] = spec.port;
      if (spec.port == 0) {
        struct sockaddr_storage ss {};
        socklen_t slen = sizeof(ss);
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
        io_uring_prep_cmd_getsockname(s, static_cast<int>(slot),
                                      reinterpret_cast<struct sockaddr*>(&ss), &slen, 0);
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

  // NO RFC - one slot of the reactor, so what the kernel touches carries
  // the kernel's names (rule 4: the ARGUMENT a field becomes) and what
  // only we touch says that it is ours:
  //   meminfo   getsockopt(fd, SOL_SOCKET, SO_MEMINFO, optval, optlen)
  //   addr,     accept4/getsockname(fd, addr, addrlen) - and what
  //   addrlen   Http1::Conn::peer then points into
  //   msg       struct msghdr, handed to io_uring_prep_sendmsg
  //   msg_iov,  its msg_iov and msg_iovlen, filled from an App::Plan
  //   msg_iovlen
  //   gen       ours: the generation half of user_data's tag, which is
  //             what makes a reused slot safe
  //   out/next  ours: the round on the wire and the one being built
  //
  // Ordered by alignment, not by topic - see Http1::Conn's own note. The
  // flags sat between the 8-byte members and cost 21 bytes of padding.
  struct Conn {
    int64_t deadline_s = 0;

    static constexpr size_t kRoundFloor = 64u * 1024;
    size_t round_cap = kRoundFloor;
    // The kernel writes all of these, so the landing buffer is full size
    // even though on_meminfo reads three of them. Every accept arms it,
    // so it stays inline - a pointer here would be a malloc per
    // connection to save 36 bytes.
    uint32_t meminfo[SK_MEMINFO_VARS] = {};

    // The peer's address, materialised only where it is going to be
    // read. arm_peer runs for a logged TCP connection and nothing else,
    // so a unix listener - and every server started without --log -
    // carries a null pointer here instead of a sockaddr_storage, which
    // is 128 bytes of which __ss_padding is 118. Kept for the slot's
    // life once made, like FileIo below and for the same reason:
    // Http1::Conn::peer points into it, and reset() clears peer_len
    // rather than the pointer.
    struct PeerAddr {
      socklen_t addrlen = 0;
      struct sockaddr_storage addr {};
    };
    std::unique_ptr<PeerAddr> peer;

    std::string out;
    std::string next;

    // response.file's one in-flight open. Lazy like everything else here -
    // most connections never open a file, and `struct statx` alone is ~256
    // bytes that used to sit inline on every slot regardless. Allocated on
    // first use (arm_file_open, right after app_.file_take() says a file is
    // actually wanted) and kept for the slot's life rather than freed on
    // every close: it "outlives a torn-down connection by one completion"
    // (see file_reading below), so tearing it down on close would race that
    // in-flight completion.
    //
    // unique_ptr, not a raw pointer, and for the same reason iov below
    // already is one: conns_ is a std::vector, and a raw pointer
    // plus a hand-written destructor would delete the implicit move
    // constructor a vector resize needs, falling back to a copy - which a
    // unique_ptr member refuses to compile, exactly like iov already
    // refuses it. unique_ptr keeps the move and needs no
    // destructor of its own.
    // NO RFC - this is the kernel's ABI, so the fields carry the names of
    // the ARGUMENTS they become:
    //
    //   io_uring_prep_read(sqe, fd, buf + filled, nbytes - filled,
    //                      offset + filled)
    //   io_uring_prep_statx(sqe, fd, "", AT_EMPTY_PATH, mask, &stx)
    //
    // Two of them are not arguments and say so.
    struct FileIo {
      // A PLAIN fd, not a direct descriptor: statx is the only op in this
      // chain the kernel does not accept a fixed file for, and statting the
      // OPENED fd (AT_EMPTY_PATH) is what keeps size and mtime describing
      // the bytes that were actually confined - a statx by path would
      // resolve a second time, unguarded.
      int fd = -1;
      // Not an argument: how much of `nbytes` has arrived. A read may come
      // back short, so the next one resumes at buf + filled.
      size_t filled = 0;
      size_t nbytes = 0;
      // Where in the FILE this window starts. Earlier windows advanced it,
      // so the kernel gets offset + filled and stx_size ends the chain.
      size_t offset = 0;
      size_t stx_size = 0;
      // Not an argument: a read whose buffer the App still owns. It
      // outlives a torn-down connection by one completion, so nothing may
      // hand that buffer back or resize it while this stands.
      bool reading = false;
      struct statx stx {};
    };
    std::unique_ptr<FileIo> file_io;

    // Not ABI: our own cap, one segment more than a Plan can hold, for
    // the head that rides in front of it.
    static constexpr unsigned kMsgIovMax = App::Plan::kSegs + 1;
    size_t plan_byte_total = 0;
    struct msghdr msg {};

    unsigned msg_iovlen = 0;
    // How much of `out` the kernel has already taken. Only ever non-zero
    // on an offloaded connection, which is the only one that resumes a
    // send; everywhere else MSG_WAITALL makes one send the whole round.
    // A plan resumes by advancing its own iovecs - see plan_drop_front.
    size_t out_sent = 0;
    uint16_t gen = 0;
    uint8_t listener = 0;
    bool live = false;
    bool sending = false;
    bool close_after_send = false;
    bool idle = false;

    typename App::Conn app;

    std::unique_ptr<struct iovec[]> msg_iov;

    // Everything TLS on this connection, and nothing on a connection that
    // is not one - most servers run a plaintext listener beside the TLS
    // one, and a cleartext slot pays a pointer.
    //
    // The exchange is freed the moment the keys are copied out: it holds
    // an OpenSSL SSL and its buffers, which is the largest thing this
    // process would otherwise carry per connection, and after the
    // handover there is nothing left for it to do. What outlives it is
    // `info`, because the setsockopt the kernel is still working on
    // points into it.
    struct Tls {
      ktls_exchange* x = nullptr;
      // The two crypto_info blobs, copied out of the exchange. The
      // largest is ChaCha20-Poly1305: 12 iv, 32 key, 0 salt, 8 rec_seq
      // plus the 4-byte header.
      unsigned char info[2][64] = {};
      size_t info_len[2] = {};
      // recvmsg needs a msghdr that outlives the submit, and a multishot
      // one outlives many completions; the kernel reads namelen and
      // controllen out of it to size what it writes into each buffer.
      struct msghdr recv_msg {};
      // RFC 8446 6.1's close_notify, kept here for the same reason as
      // recv_msg: it is submitted and then waited for, so the header,
      // the control buffer and the alert itself all outlive the call
      // that spelled them.
      struct msghdr bye_msg {};
      struct iovec bye_iov {};
      unsigned char bye[2] = {1, 0};  // warning, close_notify
      unsigned char bye_control[CMSG_SPACE(1)] = {};
      // RFC 8446 4.6.1: plaintext a peer put in the same flight as its
      // Finished. The kernel's stream starts at sequence zero and cannot
      // be handed a backlog, so this waits here until the socket has both
      // keys and then goes to the App ahead of anything the wire brings.
      std::string early;
      // RFC 8446 5.5, counted here because after the handover the kernel
      // writes the records and does not count for us. What we know is
      // what we fed it: every send is at least one record and at most
      // ceil(len / 16384), and the larger of those is what is charged,
      // so the rekey comes early rather than late. Zero limit - ChaCha -
      // never charges anything.
      uint64_t tx_records = 0;
      uint64_t tx_limit = 0;
      bool handshaking = true;
      bool offloaded = false;
      ~Tls() { ktls_exchange_free(x); }
    };
    std::unique_ptr<Tls> tls;
  };

  // The reactor cannot go on, and it is not this library's place to
  // decide what that means for the process - it is embedded, and the
  // process belongs to somebody else. So it raises, and the embedder's
  // Ruby sees Webmachine::Error and chooses. There is no second branch:
  // init() refuses a RingConfig without a VM, so this always has one.
  // A failure that belongs to ONE connection. It throws, and the
  // completion handler below catches it, says what happened and closes
  // that connection - the process belongs to somebody else, so one
  // peer's bad day is not its end (fatal, below, is for when it is).
  //
  // `what` is always a string literal: the once-only reporting keys on
  // the pointer, so two calls with the same literal are the same fault.
  struct ConnFailed {
    const char* what;
    int err;  // a negative errno where the kernel gave one, 0 where it did not
  };
  [[noreturn]] static void conn_failed(const char* what, int err = 0) {
    throw ConnFailed{what, err};
  }

  // Once per distinct reason, so a peer that can provoke one cannot
  // provoke a line per attempt. The error log is where these belong and
  // gets every one; stderr gets the first of each, because a server run
  // without --log still has an operator who needs to know.
  void say_connection_failed(const ConnFailed& f, const Conn& c) {
    Logger* el = app_.error_log();
    if (el != nullptr && el->enabled) {
      char why[192];
      const int n = std::snprintf(why, sizeof why, "%s%s%s", f.what, f.err < 0 ? ": " : "",
                                  f.err < 0 ? std::strerror(-f.err) : "");
      log_internal_error(
          *el, {c.peer != nullptr
                    ? std::string_view{reinterpret_cast<const char*>(&c.peer->addr),
                                       static_cast<size_t>(c.peer->addrlen)}
                    : std::string_view{},
                {},
                {why, static_cast<size_t>(n < 0 ? 0 : n)},
                0});
    }
    for (unsigned i = 0; i < said_count_; i++) {
      if (said_[i] == f.what) return;
    }
    if (said_count_ < kSaidMax) said_[said_count_++] = f.what;
    std::fprintf(stderr, "webmachine: %s%s%s (said once)\n", f.what, f.err < 0 ? ": " : "",
                 f.err < 0 ? std::strerror(-f.err) : "");
  }

  [[noreturn]] void fatal(const char* what) {
    mrb_raise(mrb_, E_WM_ERROR(mrb_), what);
    // mruby declares mrb_raise mrb_noreturn, but that macro (common.h)
    // resolves to NOTHING under -std=c++20: it asks for __GNUC__ &&
    // !__STRICT_ANSI__, and a strict -std= (rather than -std=gnu=) defines
    // __STRICT_ANSI__. So the compiler cannot see what is true either way -
    // with MRB_USE_CXX_EXCEPTION the raise throws, without it it longjmps -
    // and warns that a [[noreturn]] function returns. This says it instead.
    __builtin_unreachable();
  }

  // Never null on return: a full SQ is drained by submitting it, and the
  // retry then has room. io_uring_enter(2) can refuse that submit, and
  // its ANSWER is the thing worth reading - EINTR and EAGAIN are ordinary
  // and retried, EBUSY means the CQ is full and completions must be
  // reaped before anything else can go in, which this call cannot do
  // re-entrantly. Ignoring the answer, as this did, turned a recoverable
  // ring into "broken" and then killed the process over it.
  struct io_uring_sqe* sqe() {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (WM_LIKELY(s != nullptr)) return s;
    for (int attempt = 0; attempt < 8; attempt++) {
      const int rc = io_uring_submit(&ring_);
      if (rc < 0 && rc != -EINTR && rc != -EAGAIN) {
        char msg[160];
        std::snprintf(msg, sizeof msg,
                      "SQ (%u entries) full and io_uring_enter refused it: %s",
                      sq_entries_, std::strerror(-rc));
        fatal(msg);
      }
      s = io_uring_get_sqe(&ring_);
      if (WM_LIKELY(s != nullptr)) return s;
    }
    char msg[160];
    std::snprintf(msg, sizeof msg, "SQ (%u entries) stuck after 8 submits", sq_entries_);
    fatal(msg);
  }

  static constexpr uint32_t kStreamAccess = 0;
  static constexpr uint32_t kStreamError = 1;

  // Both streams, once per round, riding the submit that was happening anyway.
  void flush_log() {
    flush_access();
    flush_error();
  }

  // The whole batch in ONE send: small, constant-shaped records.
  void flush_access() {
    if (log_fd_ < 0) return;
    Logger* al = app_.access_log();
    if (al == nullptr || al->in_flight || al->pending.empty()) return;
    al->pending.swap(al->flight);
    al->in_flight = true;
    arm_access_write(al);
  }
  // send, not write: a dead daemon must be -EPIPE in a CQE, not a SIGPIPE.
  void arm_access_write(Logger* al) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_send(s, log_fd_, al->flight.data(), al->flight.size(), MSG_NOSIGNAL);
    io_uring_sqe_set_data64(s, detail::tag(detail::kLog, 0, kStreamAccess));
  }

  // ONE record per flush, as two linked sends.
  void flush_error() {
    if (err_fd_ < 0) return;
    Logger* el = app_.error_log();
    if (el == nullptr || el->in_flight || el->pending.size() < sizeof(ErrRec)) return;
    ErrRec r;
    std::memcpy(&r, el->pending.data(), sizeof r);
    const size_t whole = sizeof(ErrRec) + r.dynamic_len;
    if (el->pending.size() < whole) return;
    el->flight.assign(el->pending, 0, whole);
    el->pending.erase(0, whole);
    el->in_flight = true;
    arm_error_write(el);
  }
  // MSG_WAITALL is what makes the LINK safe: IO_LINK breaks only on FAILURE,
  // and a short send is not one.
  void arm_error_write(Logger* el) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_send(s, err_fd_, el->flight.data(), sizeof(ErrRec),
                       MSG_NOSIGNAL | MSG_WAITALL);
    s->flags |= IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kLog, 1, kStreamError));
    s = sqe();
    io_uring_prep_send(s, err_fd_, el->flight.data() + sizeof(ErrRec),
                       el->flight.size() - sizeof(ErrRec), MSG_NOSIGNAL | MSG_WAITALL);
    io_uring_sqe_set_data64(s, detail::tag(detail::kLog, 0, kStreamError));
  }

  // THE RULE: every line formatted lands. A refused write is a named refusal.
  void on_log(uint16_t gen, uint32_t stream, struct io_uring_cqe* cqe) {
    Logger* lg = stream == kStreamError ? app_.error_log() : app_.access_log();
    if (lg == nullptr) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      if (stream == kStreamError && cqe->res == -ECANCELED) return;
      char msg[160];
      std::snprintf(msg, sizeof msg, "%s log write failed: %s - refusing to drop lines",
                    stream == kStreamError ? "error" : "access", std::strerror(-cqe->res));
      fatal(msg);
    }
    if (stream == kStreamError) {
      if (gen == 1) return;
      lg->flight.clear();
      lg->in_flight = false;
      return;
    }
    const size_t took = static_cast<size_t>(cqe->res);
    if (WM_UNLIKELY(took < lg->flight.size())) {
      lg->flight.erase(0, took);
      arm_access_write(lg);
      return;
    }
    lg->flight.clear();
    lg->in_flight = false;
  }

  // The certificate a TLS listener answers with, and the two suites this
  // build speaks. Once per listener, at boot: every exchange this
  // listener ever opens is opened from it.
  bool setup_listener_keys(uint32_t li, const ListenerSpec& spec, char* err, size_t errlen) {
    if (spec.cert_pem == nullptr) return true;
    // The certificate BEFORE the kernel, deliberately: both can be wrong
    // at once, and the one the operator can fix is the one worth saying.
    // It also means a machine without the module still checks the config.
    ktls_keys* k = ktls_keys_server(spec.cert_pem, spec.cert_len, spec.key_pem, spec.key_len);
    if (k == nullptr) {
      std::snprintf(err, errlen, "listener %u certificate: %s", li, ktls_last_error());
      return false;
    }
    // AES first where the machine has the instructions, ChaCha first
    // otherwise (.DESIGN.md "Two suites, and why not three"). Said out
    // loud because it decides whether a NIC can ever take the record
    // layer over, and because it is not otherwise visible from outside.
    const bool aes_is_fast = ktls_aes_is_fast();
    std::fprintf(stderr, "webmachine: listener %u offers %s first (aes instructions: %s)\n", li,
                 aes_is_fast ? "TLS_AES_128_GCM_SHA256" : "TLS_CHACHA20_POLY1305_SHA256",
                 aes_is_fast ? "yes" : "no");
    const char* suites = aes_is_fast
                             ? "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
                             : "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    if (ktls_keys_set_ciphers(k, suites) != 0) {
      std::snprintf(err, errlen, "listener %u ciphers: %s", li, ktls_last_error());
      ktls_keys_free(k);
      return false;
    }
    // Both, in preference order. Nothing downstream reads the answer:
    // RFC 9113 3.4's preface is the first thing an h2 client sends, and
    // Http1::feed_parse already decides on it - over TLS those bytes
    // arrive exactly as they do in the clear.
    static const char* const kProtocols[] = {"h2", "http/1.1"};
    if (ktls_keys_set_alpn(k, kProtocols, 2) != 0) {
      std::snprintf(err, errlen, "listener %u alpn: %s", li, ktls_last_error());
      ktls_keys_free(k);
      return false;
    }
    if (!ktls_available()) {
      const int rc = ktls_load_module();
      if (rc != 0 || !ktls_available()) {
        std::snprintf(err, errlen,
                      "listener %u serves TLS and this kernel has no tls ULP "
                      "(modprobe tls): %s",
                      li, ktls_last_error());
        ktls_keys_free(k);
        return false;
      }
    }
    tls_keys_[li] = k;
    return true;
  }

  // The listeners leave through the ring; idempotent, or a later accept
  // would lose its slot.
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

  // Multishot accept_direct against the fixed listener slot.
  void arm_accept(uint32_t li) {
    if (draining_) return;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_multishot_accept_direct(s, listener_base_ + li, nullptr, nullptr, 0);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kAccept, 0, li));
  }

  // Room for the ONE cmsg an offloaded socket carries, TLS_GET_RECORD_TYPE.
  static constexpr size_t kTlsCmsgSpace = CMSG_SPACE(sizeof(unsigned char));

  // Multishot recv out of the buffer ring, bundles where the kernel offers
  // them - and two other shapes for a connection that is doing TLS.
  void arm_recv(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    if (WM_UNLIKELY(c.tls != nullptr)) {
      if (!c.tls->offloaded) {
        // ONE completion at a time while the exchange runs. The moment it
        // is done this process must stop reading: bytes it takes off the
        // socket after that are records the kernel's own record layer is
        // about to be made responsible for, and nothing here could decrypt
        // them once the exchange is freed. A multishot recv has no pause,
        // so the handshake does not use one.
        io_uring_prep_recv(s, static_cast<int>(idx), nullptr, 0, 0);
        s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
        s->buf_group = kBufGroup;
        io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
        return;
      }
      // Offloaded: never a plain recv (.DESIGN.md "Never a plain recv on an
      // offloaded socket"). A record that is not application data is EIO on
      // recv and a control message on recvmsg. The kernel sizes what it
      // writes into each buffer from these two lengths, so the msghdr has to
      // outlive the submit - it lives in Tls for that reason.
      c.tls->recv_msg = msghdr{};
      c.tls->recv_msg.msg_controllen = kTlsCmsgSpace;
      io_uring_prep_recvmsg_multishot(s, static_cast<int>(idx), &c.tls->recv_msg, 0);
      s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
      s->buf_group = kBufGroup;
      io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
      return;
    }
    io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
    s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    s->buf_group = kBufGroup;
    if (bundles_) s->ioprio |= IORING_RECVSEND_BUNDLE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
  }

  // The handshake, and the only thing this connection does until it is
  // over. mruby-ktls names no descriptor: bytes that arrived go in through
  // feed, bytes that must go out come back through take, and the socket
  // stays the reactor's - so what comes out of here is an ordinary send on
  // the same slot, through the same ring, as everything else.
  void tls_advance(uint32_t idx) {
    Conn& c = conns_[idx];
    ktls_step step = KTLS_READING;
    if (WM_UNLIKELY(ktls_exchange_step(c.tls->x, &step) != 0)) {
      conn_failed("tls: the key exchange failed");
    }
    // Unconditional and after the step, because ktls.h says a step that
    // answers KTLS_READING may still owe bytes.
    std::string& sink = c.sending ? c.next : c.out;
    for (;;) {
      char buf[4096];
      const size_t n = ktls_exchange_take(c.tls->x, buf, sizeof buf);
      if (n == 0) break;
      sink.append(buf, n);
    }
    if (step != KTLS_DONE) {
      // EXACTLY ONE read is armed at a time, and whoever writes last
      // arms it: a flight going out means on_send does, because two
      // reads on one connection would feed the exchange two halves of
      // the peer's next flight in whatever order they completed.
      if (c.sending || !c.out.empty()) {
        if (!c.sending) arm_send(idx);
        return;
      }
      arm_recv(idx);
      return;
    }
    // Everything the exchange still holds is read HERE, in the order
    // ktls.h asks for: the backlog first, because draining it can consume
    // a post-handshake record, and the crypto_info last, because that is
    // where the record sequence is finally settled.
    c.tls->handshaking = false;
    for (;;) {
      char buf[4096];
      const size_t n = ktls_exchange_backlog(c.tls->x, buf, sizeof buf);
      if (n == 0) break;
      c.tls->early.append(buf, n);
    }
    for (int dir = 0; dir < 2; dir++) {
      size_t len = 0;
      const void* info = ktls_crypto_info(c.tls->x, static_cast<ktls_direction>(dir), &len);
      if (WM_UNLIKELY(info == nullptr || len > sizeof c.tls->info[dir])) {
        conn_failed("tls: the agreed keys are not a shape the kernel takes");
      }
      std::memcpy(c.tls->info[dir], info, len);
      c.tls->info_len[dir] = len;
    }
    // The SSL and its buffers go now - the largest thing this process
    // would otherwise carry per connection, and nothing above still reads
    // from them. The exchange itself stays for the connection's life,
    // because the traffic secrets are what answers a KeyUpdate.
    ktls_exchange_release(c.tls->x);

    // The last flight is already TLS records. It has to reach the wire as
    // itself - from the TLS_TX setsockopt on, the kernel encrypts what this
    // process sends, and encrypting them twice is what a peer would see.
    // A send already in flight counts: what it did not take is in c.next.
    if (c.sending || !c.out.empty()) {
      if (!c.sending) arm_send(idx);
      return;
    }
    tls_handover(idx);
  }

  // A key per direction, linked so the order is the kernel's to keep
  // rather than two completions to sort out. The ULP went on at accept.
  // The options go on the DIRECT descriptor through the ring, like every
  // other option this reactor sets.
  void tls_handover(uint32_t idx) {
    Conn& c = conns_[idx];
    if (io_uring_sq_space_left(&ring_) < 2) io_uring_submit(&ring_);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_TX), c.tls->info[KTLS_TX],
                           static_cast<uint32_t>(c.tls->info_len[KTLS_TX]));
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsTx, c.gen, idx));

    s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_RX), c.tls->info[KTLS_RX],
                           static_cast<uint32_t>(c.tls->info_len[KTLS_RX]));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsRx, c.gen, idx));
  }

  // RFC 8446 4.6.3, answered: turn the receive secret one notch and put
  // the new crypto_info on the socket. The kernel restarts that
  // direction's sequence at zero, which is what a key change leaves,
  // and the exchange keeps the secret precisely for this - it is why
  // ktls_exchange_release exists rather than a free.
  //
  // ULP is already on, so this is one option and not a chain, and the
  // read is armed again only once the kernel has the key.
  void tls_next_receive_key(uint32_t idx) {
    Conn& c = conns_[idx];
    if (WM_UNLIKELY(ktls_next_key(c.tls->x, KTLS_RX) != 0)) {
      conn_failed("tls: the key update could not be answered");
    }
    size_t len = 0;
    const void* info = ktls_crypto_info(c.tls->x, KTLS_RX, &len);
    if (WM_UNLIKELY(info == nullptr || len > sizeof c.tls->info[KTLS_RX])) {
      begin_close(idx);
      return;
    }
    std::memcpy(c.tls->info[KTLS_RX], info, len);
    c.tls->info_len[KTLS_RX] = len;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_RX), c.tls->info[KTLS_RX],
                           static_cast<uint32_t>(len));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsRx, c.gen, idx));
  }

  // The last of the three. From here the socket is the kernel's record
  // layer and this connection is an ordinary one again - except that its
  // recv is a recvmsg, and that anything the peer pipelined behind its
  // Finished has been waiting and goes first.
  void on_tls_ready(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen || c.tls == nullptr) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      conn_failed(c.tls->offloaded ? "tls: setsockopt(TLS_RX) for a key update"
                                   : "tls: setsockopt(TLS_RX)",
                  cqe->res);
    }
    // A KeyUpdate lands here too - same option, same completion - and
    // there is no backlog and no deadline to reset for that one.
    if (c.tls->offloaded) {
      arm_recv(idx);
      return;
    }
    c.tls->offloaded = true;
    c.tls->tx_limit = ktls_record_limit(c.tls->x);
    c.tls->tx_records = 0;
    c.deadline_s = now_s_ + header_timeout_;
    // Once per process, and it is the line that says the whole design
    // works: from here this socket's record layer is the kernel's.
    if (!tls_handed_over_said_) {
      tls_handed_over_said_ = true;
      std::fprintf(stderr, "webmachine: tls: a socket is the kernel's now (%s, said once)\n",
                   ktls_exchange_cipher(c.tls->x) != nullptr ? ktls_exchange_cipher(c.tls->x)
                                                             : "?");
    }
    if (!c.tls->early.empty()) {
      std::string early;
      early.swap(c.tls->early);
      deliver(idx, early.data(), early.size(), true);
      if (!c.live) return;
    }
    arm_recv(idx);
  }

  // RFC 8446 5.5: a send is at least one record and at most one per
  // 16384 bytes of it, and the larger is what is charged - the count has
  // to be an over-estimate or it is not a bound.
  static void tls_charge_records(Conn& c, size_t bytes) {
    if (c.tls->tx_limit == 0) return;
    static constexpr size_t kRecordPlaintextMax = 16384;
    const uint64_t records = bytes == 0 ? 1 : (bytes + kRecordPlaintextMax - 1) / kRecordPlaintextMax;
    c.tls->tx_records += records;
  }

  // The send key, turned before the limit rather than after it, and only
  // where no send is in flight - the kernel must not be writing under a
  // key that is being replaced. ktls_record_limit already answers HALF of
  // what the RFC allows, so there is room to get here.
  bool tls_turn_send_key(uint32_t idx) {
    Conn& c = conns_[idx];
    if (c.tls == nullptr || !c.tls->offloaded) return false;
    if (c.tls->tx_limit == 0 || c.tls->tx_records < c.tls->tx_limit) return false;
    if (WM_UNLIKELY(ktls_next_key(c.tls->x, KTLS_TX) != 0)) {
      conn_failed("tls: the send key could not be turned before its record limit");
    }
    size_t len = 0;
    const void* info = ktls_crypto_info(c.tls->x, KTLS_TX, &len);
    if (WM_UNLIKELY(info == nullptr || len > sizeof c.tls->info[KTLS_TX])) {
      conn_failed("tls: the turned send key is not a shape the kernel takes");
    }
    std::memcpy(c.tls->info[KTLS_TX], info, len);
    c.tls->info_len[KTLS_TX] = len;
    c.tls->tx_records = 0;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_TX), c.tls->info[KTLS_TX],
                           static_cast<uint32_t>(len));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsTxKey, c.gen, idx));
    return true;
  }

  // The new key is on the socket; the round goes on from where it waited.
  void on_tls_tx_key(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;
    if (WM_UNLIKELY(cqe->res < 0)) conn_failed("tls: setsockopt(TLS_TX) for a record limit", cqe->res);
    send_done(idx);
  }

  // What the kernel took, dropped off the front of a plan: whole segments
  // go, the first partial one is trimmed. Nothing is allocated and
  // nothing copied - the segments that stay point at the same asset
  // mappings and lent Strings they already did.
  static void plan_drop_front(Conn& c, size_t took) {
    unsigned seg = 0;
    while (seg < c.msg_iovlen && took >= c.msg_iov[seg].iov_len) {
      took -= c.msg_iov[seg].iov_len;
      seg++;
    }
    if (seg < c.msg_iovlen && took != 0) {
      c.msg_iov[seg].iov_base = static_cast<char*>(c.msg_iov[seg].iov_base) + took;
      c.msg_iov[seg].iov_len -= took;
    }
    const unsigned left = c.msg_iovlen - seg;
    for (unsigned i = 0; i < left; i++) c.msg_iov[i] = c.msg_iov[seg + i];
    c.msg_iovlen = left;
  }

  // One sendmsg for the round; MSG_MORE when the App still owes bytes.
  //
  // MSG_WAITALL where the kernel takes it: it finishes a short send
  // itself, so the round is one operation and there is no offset to
  // carry. An OFFLOADED connection cannot have it - tls_sw_sendmsg
  // answers EOPNOTSUPP for any flag outside MSG_MORE, MSG_DONTWAIT,
  // MSG_NOSIGNAL, MSG_SPLICE_PAGES and MSG_EOR - so that one asks for no
  // retry and resumes itself, out of `out_sent` or its own iovecs.
  //
  // The lend survives either way: resource.cpp freezes and roots the
  // String and zc_release hands it back when the ROUND drains, never
  // when one send returns.
  void arm_send(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    const bool resumes = c.tls != nullptr && c.tls->offloaded;
    const int flags = MSG_NOSIGNAL | (resumes ? 0 : MSG_WAITALL) |
                      (app_.pending(c.app) ? MSG_MORE : 0);
    if (c.msg_iovlen == 0) {
      io_uring_prep_send(s, static_cast<int>(idx), c.out.data() + c.out_sent,
                         c.out.size() - c.out_sent, flags);
    } else {
      c.msg = msghdr{};
      c.msg.msg_iov = c.msg_iov.get();
      c.msg.msg_iovlen = c.msg_iovlen;
      io_uring_prep_sendmsg(s, static_cast<int>(idx), &c.msg, flags);
    }
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kSend, c.gen, idx));
    c.sending = true;
  }

  // One bit per slot, so the once-a-second reap can find the live ones
  // without reading a Conn to ask. The table is sized by RLIMIT_NOFILE
  // (derive_max_conns), not by the peers actually here, so walking it
  // touched a cache line per slot however few were connected.
  void live_set(uint32_t idx) { live_bits_[idx >> 6] |= 1ULL << (idx & 63); }
  void live_clear(uint32_t idx) { live_bits_[idx >> 6] &= ~(1ULL << (idx & 63)); }

  // RFC 8446 6.1: without it a peer cannot tell a finished stream from a
  // truncated one. Nothing here builds a record - the kernel does, from
  // the type this control message names - so it is a sendmsg like any
  // other, linked ahead of the shutdown that follows it.
  //
  // Only where the socket already IS the kernel's: before the handover
  // there is no key to encrypt an alert with, and a cleartext one would
  // be noise on the wire.
  void arm_close_notify(uint32_t idx) {
    Conn& c = conns_[idx];
    if (c.tls == nullptr || !c.tls->offloaded) return;
    const int cmsg_type = ktls_record_type_set_cmsg();
    if (WM_UNLIKELY(cmsg_type < 0)) return;

    typename Conn::Tls& t = *c.tls;
    t.bye_iov.iov_base = t.bye;
    t.bye_iov.iov_len = sizeof t.bye;
    t.bye_msg = msghdr{};
    t.bye_msg.msg_iov = &t.bye_iov;
    t.bye_msg.msg_iovlen = 1;
    t.bye_msg.msg_control = t.bye_control;
    t.bye_msg.msg_controllen = sizeof t.bye_control;
    struct cmsghdr* cm = CMSG_FIRSTHDR(&t.bye_msg);
    cm->cmsg_level = ktls_sol_tls();
    cm->cmsg_type = cmsg_type;
    cm->cmsg_len = CMSG_LEN(1);
    if (WM_UNLIKELY(ktls_record_type_encode(KTLS_RECORD_ALERT, CMSG_DATA(cm), 1) != 1)) return;
    t.bye_msg.msg_controllen = CMSG_SPACE(1);

    struct io_uring_sqe* s = sqe();
    io_uring_prep_sendmsg(s, static_cast<int>(idx), &t.bye_msg, MSG_NOSIGNAL);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsBye, c.gen, idx));
  }

  // shutdown BEFORE close_direct, linked: close_direct alone leaves the
  // socket open and the peer never sees FIN.
  void begin_close(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.live) return;
    if (c.sending) {
      c.close_after_send = true;
      return;
    }
    // A transfer dying under a client is exactly the event an operator
    // wants in the log, so the line is owed here too - with the bytes that
    // really went out.
    app_.file_abandon(c.app);
    // The exchange goes now - it is the biggest thing this slot holds and
    // nothing submitted points into it. The struct around it does NOT: a
    // handover's three setsockopts read c.tls->info and a multishot
    // recvmsg writes through c.tls->recv_msg, and either may still be with
    // the kernel. It goes when the slot is accepted into again.
    if (c.tls != nullptr) {
      ktls_exchange_free(c.tls->x);
      c.tls->x = nullptr;
    }
    c.live = false;
    live_clear(idx);
    if (live_ != 0) live_--;
    if (io_uring_sq_space_left(&ring_) < 3) io_uring_submit(&ring_);
    arm_close_notify(idx);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_shutdown(s, static_cast<int>(idx), SHUT_RDWR);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kShutdown, c.gen, idx));
    s = sqe();
    io_uring_prep_close_direct(s, idx);
    io_uring_sqe_set_data64(s, detail::tag(detail::kClose, c.gen, idx));
  }

  // A new peer: its slot, its clocks, and the setsockopts TCP wants.
  void on_accept(uint32_t li, struct io_uring_cqe* cqe) {
    if (!(cqe->flags & IORING_CQE_F_MORE)) arm_accept(li);
    if (cqe->res < 0) return;
    const uint32_t idx = static_cast<uint32_t>(cqe->res);
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    c.gen++;
    c.live = true;
    live_set(idx);
    live_++;
    c.sending = false;
    c.close_after_send = false;
    c.idle = false;
    c.deadline_s = now_s_ + header_timeout_;
    c.listener = static_cast<uint8_t>(li);
    c.out.clear();
    c.out_sent = 0;
    c.next.clear();
    c.app.reset(static_cast<uint8_t>(li), !unix_listener_[li]);
    if (!unix_listener_[li]) {
      static const int kOne = 1;
      struct io_uring_sqe* s = sqe();
      io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx),
                             IPPROTO_TCP, TCP_NODELAY, const_cast<int*>(&kOne), sizeof(kOne));
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, idx));
    }
    // A listener with a certificate hands its peer an exchange before it
    // hands it anything else; arm_recv reads this to know which shape it
    // is submitting, so it is set before the first read is armed.
    c.tls.reset();
    if (WM_UNLIKELY(tls_keys_[li] != nullptr)) {
      c.tls.reset(new typename Conn::Tls());
      c.tls->x = ktls_exchange_open(tls_keys_[li], KTLS_SERVER);
      if (WM_UNLIKELY(c.tls->x == nullptr)) {
        begin_close(idx);
        return;
      }
      // The ULP goes on HERE, not at the handover - the order the kernel
      // documents and the one OpenSSL's own ktls_enable uses. Without
      // keys it forwards bytes unchanged, so the handshake reads and
      // writes exactly as it would have; TLS_TX and TLS_RX are what
      // install the record layer later.
      //
      // At the handover it was too late: tls_init refuses a socket that
      // is not ESTABLISHED, and by then a peer that finished its own
      // handshake and hung up has already put this one in CLOSE_WAIT.
      // Here the accept has just returned, so there is no such window.
      static const char kUlp[] = "tls";
      struct io_uring_sqe* u = sqe();
      io_uring_prep_cmd_sock(u, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), IPPROTO_TCP,
                             TCP_ULP, const_cast<char*>(kUlp), sizeof kUlp);
      u->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(u, detail::tag(detail::kTlsUlp, c.gen, idx));
    }
    arm_meminfo(idx);
    if (log_fd_ >= 0 && !unix_listener_[li]) arm_peer(idx);
    arm_recv(idx);
  }

  // Wire bytes to the App. Kernel-supplied ids and lengths are checked
  // before use; ENOBUFS re-arms rather than hanging the connection.
  // Nothing arrived that can be parsed: a peer that left, a kernel that
  // ran out of buffers, a completion whose own numbers do not hold. None
  // of it is the path a request takes, so none of it is in one.
  void on_recv_nothing_to_parse(uint32_t idx, Conn& c, struct io_uring_cqe* cqe) {
    if (cqe->res == -ENOBUFS) {
      rearm_.push_back(idx);
      return;
    }
    if (cqe->res < 0 && c.tls != nullptr && c.tls->offloaded) {
      conn_failed("tls: recvmsg on an offloaded socket", cqe->res);
    }
    begin_close(idx);
  }

  // Bytes for a connection that has already been told to go: the buffers
  // still have to be handed back, and nothing else does.
  void on_recv_after_close(uint32_t idx, size_t total) {
    (void) idx;
    replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
  }

  void on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (WM_UNLIKELY(!c.live || c.gen != gen)) return;

    if (WM_UNLIKELY(cqe->res <= 0)) {
      on_recv_nothing_to_parse(idx, c, cqe);
      return;
    }
    if (WM_UNLIKELY(!(cqe->flags & IORING_CQE_F_BUFFER))) {
      begin_close(idx);
      return;
    }
    const uint32_t bid0 = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    const size_t total = static_cast<size_t>(cqe->res);
    if (WM_UNLIKELY(bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize)) {
      begin_close(idx);
      return;
    }
    if (WM_UNLIKELY(c.close_after_send)) {
      on_recv_after_close(idx, total);
      return;
    }
    if (WM_UNLIKELY(c.tls != nullptr)) {
      on_recv_tls(idx, bid0, total, cqe->flags);
      return;
    }
    if (WM_UNLIKELY(c.idle)) {
      c.idle = false;
      c.deadline_s = now_s_ + header_timeout_;
    }

    std::string& sink = c.sending ? c.next : c.out;
    bool closing = false;
    size_t left = total;
    uint32_t bid = bid0;
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
      if (req.iovlen != 0) {
        take_plan(c, req);
        arm_send(idx);
      } else if (!c.out.empty()) {
        arm_send(idx);
      }
    }
    // A run that named a file answered nothing yet: the open is the
    // reactor's, and its result reaches the wire through continue_conn.
    arm_file_open(idx);
    // Unless the name never reached the kernel at all - a refusal this
    // process spelled itself owes no completion, so nothing else would
    // ever come back to collect it.
    if (WM_UNLIKELY(App::file_answerable(c.app)) && !c.sending) continue_conn(idx);
    if (WM_UNLIKELY(closing)) {
      round_closed(idx, c);
      if (!c.live) return;
    }
    if (WM_UNLIKELY(!(cqe->flags & IORING_CQE_F_MORE))) rearm_.push_back(idx);
  }

  // The App will take nothing more on this connection.
  void round_closed(uint32_t idx, Conn& c) {
    if (c.tls != nullptr && c.tls->offloaded) {
      conn_failed("tls: the parser refused what the kernel decrypted", -EPROTO);
    }
    if (c.sending) c.close_after_send = true;
    else begin_close(idx);
  }

  // What a round owes once the App has seen its bytes: the answer on the
  // wire, an open the run deferred, and the close it may have asked for.
  // Shared, because bytes reach the App from three places - the buffer
  // ring, an offloaded socket's recvmsg, and the backlog a handshake left.
  void finish_round(uint32_t idx, typename App::Plan& req, bool closing) {
    Conn& c = conns_[idx];
    if (!c.sending) {
      if (req.iovlen != 0) {
        take_plan(c, req);
        arm_send(idx);
      } else if (!c.out.empty()) {
        arm_send(idx);
      }
    }
    // A run that named a file answered nothing yet: the open is the
    // reactor's, and its result reaches the wire through continue_conn.
    arm_file_open(idx);
    // Unless the name never reached the kernel at all - a refusal this
    // process spelled itself owes no completion, so nothing else would ever
    // come back to collect it.
    if (WM_UNLIKELY(App::file_answerable(c.app)) && !c.sending) continue_conn(idx);
    if (WM_UNLIKELY(closing)) round_closed(idx, c);
  }

  // ONE contiguous stretch of plaintext to the App, and the round it
  // finishes. `last` is what lets a Plan form, so a caller that has the
  // whole of what arrived says so.
  void deliver(uint32_t idx, const char* data, size_t len, bool last) {
    Conn& c = conns_[idx];
    typename App::Plan req;
    req.byte_cap = c.round_cap;
    typename App::Plan* plan = (last && !c.sending) ? &req : nullptr;
    std::string& sink = c.sending ? c.next : c.out;
    const bool closing = !app_.feed(c.app, data, len, sink, plan);
    finish_round(idx, req, closing);
  }

  // The same buffers, for a connection doing TLS. Before the handover the
  // bytes are records only the exchange can read; after it they are
  // plaintext the kernel already decrypted, and what they arrive in is a
  // recvmsg's own layout rather than the payload alone.
  void on_recv_tls(uint32_t idx, uint32_t bid0, size_t total, uint32_t flags) {
    Conn& c = conns_[idx];
    const size_t off = static_cast<size_t>(bid0) * kBufSize;
    replenish_++;

    if (c.tls->handshaking) {
      if (WM_UNLIKELY(total > kBufSize || ktls_exchange_feed(c.tls->x, pool_ + off, total) != 0)) {
        conn_failed("tls: the peer's handshake bytes were refused");
      }
      tls_advance(idx);
      return;
    }

    // Between the handshake finishing and the last of the three
    // setsockopts landing, nothing is armed and nothing may arrive - so a
    // completion here belongs to a socket that is already the kernel's.
    struct io_uring_recvmsg_out* o =
        io_uring_recvmsg_validate(pool_ + off, static_cast<int>(total), &c.tls->recv_msg);
    if (WM_UNLIKELY(o == nullptr)) {
      conn_failed("tls: a recvmsg header that does not fit its own buffer");
    }
    // A record whose plaintext did not fit, or a control message that did
    // not. Either would hand the parser a piece of something and call it
    // the whole thing, so neither is read.
    if (WM_UNLIKELY((o->flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)) {
      conn_failed("tls: a record too large for one buffer");
    }
    // An alert or a post-handshake record reaches a plain recv as EIO and
    // nothing else; here it says which it is (.DESIGN.md "Never a plain
    // recv on an offloaded socket").
    ktls_record record = KTLS_RECORD_UNKNOWN;
    for (struct cmsghdr* cm = io_uring_recvmsg_cmsg_firsthdr(o, &c.tls->recv_msg); cm != nullptr;
         cm = io_uring_recvmsg_cmsg_nexthdr(o, &c.tls->recv_msg, cm)) {
      if (cm->cmsg_level == ktls_sol_tls() && cm->cmsg_type == ktls_record_type_cmsg()) {
        record = ktls_record_type(CMSG_DATA(cm), cm->cmsg_len - CMSG_LEN(0));
      }
    }
    if (WM_UNLIKELY(record != KTLS_RECORD_DATA)) {
      // An alert ends the connection because that is what one is for -
      // close_notify included, which is the ordinary way a peer leaves.
      if (record != KTLS_RECORD_HANDSHAKE) {
        if (record == KTLS_RECORD_ALERT) {
          begin_close(idx);
          return;
        }
        conn_failed("tls: a record of no known type");
      }
      tls_next_receive_key(idx);
      return;
    }
    const void* payload = io_uring_recvmsg_payload(o, &c.tls->recv_msg);
    const size_t len =
        io_uring_recvmsg_payload_length(o, static_cast<int>(total), &c.tls->recv_msg);
    if (len != 0) {
      deliver(idx, static_cast<const char*>(payload), len, true);
      if (!c.live) return;
    }
    if (!(flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
  }

  // What the kernel took, and what is still owed.
  void on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    c.sending = false;

    if (WM_UNLIKELY(cqe->res < 0)) {
      send_refused(idx, c, cqe->res);
      return;
    }
    // MSG_WAITALL means the kernel already retried; fewer bytes than offered
    // is a dead peer, and a half-written response cannot be resumed - HTTP/1
    // has no restart point and an h2 frame cut in half breaks the whole
    // connection's framing. So the only answer is to drop it.
    const size_t took = static_cast<size_t>(cqe->res);
    const size_t offered = c.msg_iovlen != 0 ? c.plan_byte_total : c.out.size() - c.out_sent;
    if (WM_UNLIKELY(took != offered)) {
      // Nobody retried this one, so what is left is still owed and the
      // stream carries on where it stopped. That is the one thing a
      // half-written response CAN do; what it cannot do is start again.
      if (WM_UNLIKELY(c.tls != nullptr) && c.tls->offloaded) {
        send_resume(idx, c, took);
        return;
      }
      begin_close(idx);
      return;
    }
    c.deadline_s = now_s_ + send_timeout_;
    if (WM_UNLIKELY(c.tls != nullptr) && c.tls->offloaded) tls_charge_records(c, took);
    c.out.clear();
    c.out_sent = 0;
    c.msg_iovlen = 0;
    c.plan_byte_total = 0;
    // A send key at its record limit is turned HERE, where nothing is in
    // flight; what the round owes next waits for that completion. The
    // null test is at THIS side of the call so a cleartext send does not
    // make one.
    if (WM_UNLIKELY(c.tls != nullptr) && tls_turn_send_key(idx)) return;
    send_done(idx);
  }

  // A send the kernel refused outright.
  void send_refused(uint32_t idx, Conn& c, int err) {
    if (c.tls != nullptr && c.tls->offloaded) {
      conn_failed("tls: send on an offloaded socket", err);
    }
    begin_close(idx);
  }

  // Only an offloaded connection gets here: without MSG_WAITALL nobody
  // retried, so what is left is still owed and the stream carries on
  // where it stopped. That is the one thing a half-written response CAN
  // do; what it cannot do is start again.
  void send_resume(uint32_t idx, Conn& c, size_t took) {
    if (c.msg_iovlen != 0) {
      plan_drop_front(c, took);
      c.plan_byte_total -= took;
    } else {
      c.out_sent += took;
    }
    c.deadline_s = now_s_ + send_timeout_;
    tls_charge_records(c, took);
    arm_send(idx);
  }

  // What a finished send leaves owed: the rest of the round, the next
  // one, or the connection going idle. Inline in on_send, which is the
  // path every response takes; on_tls_tx_key calls it because a rekey
  // happens once per 2^23 records and may pay for the call.
  void send_done(uint32_t idx) {
    Conn& c = conns_[idx];
    // The handshake's own bytes, now on the wire as themselves. Only once
    // nothing is left may the kernel be given the write key.
    if (WM_UNLIKELY(c.tls != nullptr) && !c.tls->offloaded) {
      if (c.next.empty()) {
        if (c.tls->handshaking) arm_recv(idx);
        else tls_handover(idx);
        return;
      }
      c.out.swap(c.next);
      arm_send(idx);
      return;
    }
    if (!c.next.empty()) {
      c.out.swap(c.next);
      arm_send(idx);
      return;
    }
    if (app_.pending(c.app)) {
      arm_meminfo(idx);
      return;
    }
    continue_conn(idx);
  }

  // response.file, stage 1: openat2 against the docroot fd. RESOLVE_BENEATH
  // anchors the walk to THAT fd, so the confinement is the kernel's and not
  // this code's - no path math here, on purpose.
  void arm_file_open(uint32_t idx) {
    Conn& c = conns_[idx];
    if (c.file_io != nullptr && c.file_io->reading) return;  // its buffer is still under a live read
    const char* path = app_.file_take(c.app);
    if (path == nullptr) return;
    if (c.file_io == nullptr) c.file_io.reset(new Conn::FileIo());
    struct io_uring_sqe* s = sqe();
    io_uring_prep_openat2(s, docroot_fd(), path, const_cast<struct open_how*>(docroot_how()));
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileOpen, c.gen, idx));
  }

  // The fd leaves through the ring like every other descriptor here.
  void arm_file_close(uint32_t idx, int fd, uint16_t gen) {
    if (fd < 0) return;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_close(s, fd);
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileClose, gen, idx));
  }

  // The head is spelled; `more` is what puts it on the wire, so a connection
  // mid-send is left to on_send's own continuation.
  void file_wake(uint32_t idx) {
    if (!conns_[idx].sending) continue_conn(idx);
  }

  // ENOENT, EXDEV (RESOLVE_BENEATH), ELOOP (RESOLVE_NO_SYMLINKS), EACCES -
  // ONE answer for all of them, so probing for a symlink or a traversal
  // cannot be told apart from asking for a name that was never there.
  void on_file_open(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) {
      arm_file_close(idx, cqe->res >= 0 ? cqe->res : -1, gen);
      return;
    }
    if (cqe->res < 0) {
      app_.file_reject(c.app);
      file_wake(idx);
      return;
    }
    c.file_io->fd = cqe->res;
    c.file_io->filled = 0;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_statx(s, c.file_io->fd, "", AT_EMPTY_PATH,
                        STATX_TYPE | STATX_SIZE | STATX_MTIME, &c.file_io->stx);
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileStat, c.gen, idx));
  }

  // statx on the OPENED fd, never by path: size and mtime have to describe
  // the bytes openat2 confined, and a second resolve would not be confined.
  void on_file_stat(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    const int fd = c.file_io->fd;
    c.file_io->fd = -1;
    if (!c.live || c.gen != gen) {
      arm_file_close(idx, fd, gen);
      return;
    }
    if (cqe->res < 0) {
      arm_file_close(idx, fd, gen);
      app_.file_reject(c.app);
      file_wake(idx);
      return;
    }
    size_t want = 0;
    const bool read_owed = app_.file_stat(c.app, c.file_io->stx, &want);
    if (!read_owed || want == 0) {
      arm_file_close(idx, fd, gen);
      if (read_owed) app_.file_ready_now(c.app, 0);
      file_wake(idx);
      return;
    }
    // A large file is mapped, not read: the sends walk the mapping and the
    // fd is done with. A failed mmap is not an error - the read path below
    // serves the same bytes, only slower, and `want` is a WINDOW whatever
    // the answer here was, so falling through cannot ask for the file.
    const size_t maplen = App::file_map_len(c.app);
    if (maplen != 0) {
      void* m = ::mmap(nullptr, maplen, PROT_READ, MAP_PRIVATE, fd, 0);
      if (m != MAP_FAILED) {
        arm_file_close(idx, fd, gen);
        app_.file_mapped(c.app, static_cast<const char*>(m), maplen);
        file_wake(idx);
        return;
      }
    }
    c.file_io->fd = fd;
    c.file_io->nbytes = want;
    c.file_io->filled = 0;
    c.file_io->offset = 0;
    c.file_io->stx_size = static_cast<size_t>(c.file_io->stx.stx_size);
    arm_file_read(idx);
  }

  void arm_file_read(uint32_t idx) {
    Conn& c = conns_[idx];
    char* buf = app_.file_buffer(c.app, c.file_io->nbytes);
    c.file_io->reading = true;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_read(s, c.file_io->fd, buf + c.file_io->filled,
                       static_cast<unsigned>(c.file_io->nbytes - c.file_io->filled),
                       c.file_io->offset + c.file_io->filled);
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileRead, c.gen, idx));
  }

  // A short read is ordinary and resumes; res == 0 before the end is the
  // file shrinking under the Content-Length statx already named, which is a
  // framing lie - refused, not sent.
  void on_file_read(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    c.file_io->reading = false;
    const int fd = c.file_io->fd;
    if (!c.live || c.gen != gen) {
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
      arm_file_open(idx);
      return;
    }
    if (cqe->res < 0) {
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
      app_.file_error(c.app, std::strerror(-cqe->res));
      file_wake(idx);
      return;
    }
    c.file_io->filled += static_cast<size_t>(cqe->res);
    if (cqe->res != 0 && c.file_io->filled < c.file_io->nbytes) {
      arm_file_read(idx);
      return;
    }
    if (c.file_io->filled < c.file_io->nbytes) {
      // Short of the window with nothing left to read: the file shrank under
      // the Content-Length statx already promised. The framing would lie, so
      // the answer is refused rather than sent.
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
      app_.file_error(c.app, "the file shrank while it was read");
      file_wake(idx);
      return;
    }
    c.file_io->offset += c.file_io->filled;
    // The fd stays open while the file still owes windows; continue_conn
    // arms the next read once the round this one feeds has drained.
    if (c.file_io->offset >= c.file_io->stx_size) {
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
    }
    app_.file_ready_now(c.app, c.file_io->filled);
    file_wake(idx);
  }

  // SO_MEMINFO through the ring.
  void arm_meminfo(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_GETSOCKOPT, static_cast<int>(idx), SOL_SOCKET,
                           SO_MEMINFO, c.meminfo, sizeof(c.meminfo));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kMeminfo, c.gen, idx));
  }

  // The peer's address, through liburing's own prep - the last argument
  // is what picks the peer over this socket's own name. Only when
  // someone is logging.
  void arm_peer(uint32_t idx) {
    Conn& c = conns_[idx];
    if (c.peer == nullptr) c.peer.reset(new typename Conn::PeerAddr());
    c.peer->addrlen = sizeof(c.peer->addr);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_getsockname(s, static_cast<int>(idx),
                                  reinterpret_cast<struct sockaddr*>(&c.peer->addr),
                                  &c.peer->addrlen, 1);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kPeer, c.gen, idx));
  }
  // The peer's RAW sockaddr for the log; "-" and one line if the kernel
  // has no such cmd.
  void on_peer(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      static bool warned = false;
      if (!warned) {
        warned = true;
        std::fprintf(stderr, "webmachine: peer address unavailable (%s); %%h logs '-'\n",
                     std::strerror(-cqe->res));
      }
      return;
    }
    if (c.peer != nullptr && c.peer->addrlen > 0 &&
        static_cast<size_t>(c.peer->addrlen) <= sizeof(c.peer->addr)) {
      c.app.peer = &c.peer->addr;
      c.app.peer_len = static_cast<uint8_t>(
          c.peer->addrlen > 255 ? 255 : c.peer->addrlen);
    }
  }

  // The round's byte bound, from the socket's own books.
  void on_meminfo(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    size_t cap = Conn::kRoundFloor;
    if (WM_LIKELY(cqe->res >= 0)) {
      const uint32_t used = c.meminfo[SK_MEMINFO_WMEM_QUEUED] > c.meminfo[SK_MEMINFO_WMEM_ALLOC]
                                ? c.meminfo[SK_MEMINFO_WMEM_QUEUED]
                                : c.meminfo[SK_MEMINFO_WMEM_ALLOC];
      const uint32_t buf = c.meminfo[SK_MEMINFO_SNDBUF];
      const size_t free_b = buf > used ? buf - used : 0;
      if (free_b > cap) cap = free_b;
    }
    c.round_cap = cap;
    if (c.sending) return;
    continue_conn(idx);
  }

  // RESOLVE a plan into iovecs: a sink segment carried an OFFSET, and this
  // is the first moment the address is final.
  void take_plan(Conn& c, const typename App::Plan& req) {
    if (!c.msg_iov) {
      c.msg_iov = std::make_unique<struct iovec[]>(Conn::kMsgIovMax);
    }
    c.msg_iovlen = 0;
    c.plan_byte_total = 0;
    bool sink_covered = false;
    for (unsigned i = 0; i < req.iovlen; i++) {
      const typename App::Plan::Seg& sg = req.iov[i];
      if (sg.iov_base != nullptr) {
        c.msg_iov[c.msg_iovlen].iov_base = const_cast<char*>(sg.iov_base);
      } else {
        c.msg_iov[c.msg_iovlen].iov_base = c.out.data() + sg.off;
        sink_covered = true;
      }
      c.msg_iov[c.msg_iovlen].iov_len = sg.iov_len;
      c.plan_byte_total += sg.iov_len;
      c.msg_iovlen++;
    }
    if (!sink_covered && !c.out.empty()) {
      for (unsigned i = c.msg_iovlen; i > 0; i--) c.msg_iov[i] = c.msg_iov[i - 1];
      c.msg_iov[0].iov_base = c.out.data();
      c.msg_iov[0].iov_len = c.out.size();
      c.plan_byte_total += c.out.size();
      c.msg_iovlen++;
    }
  }

  // The delivery continuation: a fully drained sink is the one signal every
  // protocol produces. Backlog first, then the App.
  void continue_conn(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.out.empty()) {
      arm_send(idx);
      return;
    }
    typename App::Plan req;
    req.byte_cap = c.round_cap;
    if (!app_.more(c.app, c.out, req)) c.close_after_send = true;
    arm_file_open(idx);
    if (req.iovlen != 0) {
      take_plan(c, req);
      arm_send(idx);
      return;
    }
    if (!c.out.empty()) {
      arm_send(idx);
      return;
    }
    // Nothing went out this round, so the window lent to the last one is
    // off the wire and the buffer is free. THIS is the only point where the
    // next window may be read - doing it on the round that just lent the
    // buffer out overwrites the bytes still being sent.
    if (c.file_io != nullptr && c.file_io->fd >= 0 && !c.file_io->reading &&
        c.file_io->offset < c.file_io->stx_size) {
      const size_t left = c.file_io->stx_size - c.file_io->offset;
      c.file_io->nbytes = left < kResponseFileWindow ? left : kResponseFileWindow;
      c.file_io->filled = 0;
      arm_file_read(idx);
      return;
    }
    if (c.close_after_send) {
      c.close_after_send = false;
      begin_close(idx);
      return;
    }
    c.idle = true;
    c.deadline_s = now_s_ + idle_timeout_;
    // Nothing owed and nothing on the wire - the one point where handing the
    // file read buffer back cannot pull it out from under anybody.
    if ((c.file_io == nullptr || !c.file_io->reading) && !app_.pending(c.app)) {
      App::file_release(c.app);
    }
  }
  // One completion, by tag.
  void handle(struct io_uring_cqe* cqe) {
    const uint64_t ud = io_uring_cqe_get_data64(cqe);
    const uint8_t kind = static_cast<uint8_t>(ud >> 56);
    const uint16_t gen = static_cast<uint16_t>(ud >> 32);
    const uint32_t idx = static_cast<uint32_t>(ud);
    // The try is HERE and not around a dispatch() of its own: a separate
    // function took on_send and its tail back out of line, and this is
    // the hottest path in the reactor - measured, 4678 bytes of fused
    // handle became 3796 of dispatch plus 2145 of on_send plus 1598 of
    // its tail, and a bench lost 5%.
    try {
      switch (kind) {
        case detail::kAccept: on_accept(idx, cqe); break;
        case detail::kRecv: on_recv(idx, gen, cqe); break;
        case detail::kSend: on_send(idx, gen, cqe); break;
        case detail::kMeminfo: on_meminfo(idx, gen, cqe); break;
        case detail::kFileOpen: on_file_open(idx, gen, cqe); break;
        case detail::kFileStat: on_file_stat(idx, gen, cqe); break;
        case detail::kFileRead: on_file_read(idx, gen, cqe); break;
        case detail::kFileClose: break;
        case detail::kLog: on_log(gen, idx, cqe); break;
        case detail::kPeer: on_peer(idx, gen, cqe); break;
        case detail::kClose:
          if (WM_UNLIKELY(cqe->res == -ECANCELED)) {
            struct io_uring_sqe* s = sqe();
            io_uring_prep_close_direct(s, idx);
            io_uring_sqe_set_data64(s, detail::tag(detail::kClose, gen, idx));
          }
          break;
        case detail::kShutdown: break;
        // The first two only report: a failure in either cancels the rest of
        // the chain, and the third is where the socket is finally the
        // kernel's, so that is the one that acts.
        case detail::kTlsUlp:
          // ENOTCONN is the peer having left between the accept and this
          // option: a race no arrangement avoids and nobody's fault.
          if (WM_UNLIKELY(cqe->res < 0)) {
            if (cqe->res == -ENOTCONN) {
              begin_close(idx);
              break;
            }
            conn_failed("tls: setsockopt(TCP_ULP)", cqe->res);
          }
          break;
        case detail::kTlsTx:
          if (WM_UNLIKELY(cqe->res < 0)) conn_failed("tls: setsockopt(TLS_TX)", cqe->res);
          break;
        // The connection is already going; a peer that will not take the
        // alert is not a thing this end can do anything about.
        case detail::kTlsBye: break;
        case detail::kTlsRx: on_tls_ready(idx, gen, cqe); break;
        case detail::kTlsTxKey: on_tls_tx_key(idx, gen, cqe); break;
        case detail::kStop: stop_ = true; break;
        default: break;
      }
    } catch (const ConnFailed& f) {
      connection_failed(idx, f);
    }
  }

  // The one place a ConnFailed lands, whoever threw it.
  void connection_failed(uint32_t idx, const ConnFailed& f) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    say_connection_failed(f, conns_[idx]);
    begin_close(idx);
  }

  // One wait and one batch; bounded to a second even without a budget, so
  // the timeout clocks get a wake when nothing completes.
  bool step(const int64_t* deadline, bool bounded) {
    if (replenish_ != 0) {
      io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
      replenish_ = 0;
    }
    flush_log();
    if (bounded) {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      const int64_t left =
          *deadline - (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec);
      struct io_uring_cqe* first = nullptr;
      if (left <= 0) {
        io_uring_submit(&ring_);
      } else {
        struct __kernel_timespec ts {left / 1000000000, left % 1000000000};
        io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
      }
    } else {
      struct __kernel_timespec ts {1, 0};
      struct io_uring_cqe* first = nullptr;
      io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
    }
    {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      now_s_ = static_cast<int64_t>(now.tv_sec);
    }
    app_.on_tick();
    bool worked = false;
    struct io_uring_cqe* cqe = nullptr;
    while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
      handle(cqe);
      io_uring_cqe_seen(&ring_, cqe);
      worked = true;
      if (bounded) {
        struct timespec now {};
        ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        if (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec >= *deadline) break;
      }
    }
    if (!rearm_.empty()) {
      for (uint32_t idx : rearm_) {
        Conn& c = conns_[idx];
        if (c.live && !c.close_after_send) arm_recv(idx);
      }
      rearm_.clear();
    }
    if (now_s_ != last_reap_s_) {
      last_reap_s_ = now_s_;
      const size_t nwords = live_bits_.size();
      for (size_t w = 0; w < nwords; w++) {
        // begin_close only CLEARS bits and no accept runs inside this
        // sweep, so a snapshot can go stale in one direction only - the
        // c.live guard below still catches that.
        uint64_t bits = live_bits_[w];
        while (bits != 0) {
          const uint32_t i = static_cast<uint32_t>(w * 64) + __builtin_ctzll(bits);
          bits &= bits - 1;
          Conn& c = conns_[i];
          if (!c.live) continue;
          if (!c.sending && app_.timed(c.app)) {
            c.deadline_s = now_s_ + idle_timeout_;
            continue_conn(i);
            continue;
          }
          if (c.deadline_s >= now_s_) continue;
          if (c.sending) {
            if (!c.close_after_send) {
              c.close_after_send = true;
              struct io_uring_sqe* s = sqe();
              io_uring_prep_shutdown(s, static_cast<int>(i), SHUT_RDWR);
              s->flags |= IOSQE_FIXED_FILE;
              io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, i));
            }
          } else if (WM_UNLIKELY(c.tls != nullptr) && !c.tls->offloaded) {
            // A TLS connection that ran out of time before the kernel
            // ever got its keys did not just go idle.
            connection_failed(i, ConnFailed{"tls: a handshake that never finished", -ETIMEDOUT});
          } else {
            begin_close(i);
          }
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
  int log_fd_ = -1;
  int err_fd_ = -1;
  unsigned sq_entries_ = 0;
  // Whose exception this is, when the reactor has to give up. See fatal().
  mrb_state* mrb_ = nullptr;
  int backlog_ = 511;
  int header_timeout_ = 60;
  int send_timeout_ = 60;
  int idle_timeout_ = 75;
  int64_t now_s_ = 0;
  int64_t last_reap_s_ = 0;
  uint32_t max_conns_ = 0;
  uint32_t listener_base_ = 0;
  bool unix_listener_[kMaxListeners] = {};
  bool tls_handed_over_said_ = false;
  static constexpr unsigned kSaidMax = 24;
  const char* said_[kSaidMax] = {};
  unsigned said_count_ = 0;
  // Null on a listener that serves cleartext, which is also how a slot
  // knows which it is - there is no second flag to keep in step.
  ktls_keys* tls_keys_[kMaxListeners] = {};
  int bound_port_[kMaxListeners] = {};
  std::vector<std::string> unix_paths_;
  uint32_t nlisteners_ = 0;
  bool listeners_closed_ = false;
  bool draining_ = false;
  int64_t drain_deadline_ = 0;
  uint32_t live_ = 0;
  std::vector<uint64_t> live_bits_;
  char* pool_ = nullptr;
  struct io_uring_buf_ring* buf_ring_ = nullptr;
  unsigned replenish_ = 0;
  std::vector<Conn> conns_;
  std::vector<uint32_t> rearm_;
};
}

#endif
