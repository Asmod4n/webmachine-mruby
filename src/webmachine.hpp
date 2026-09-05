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
#include <coroutine>
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

// One walk of the graph in progress: the konst answers it follows, and
// which nodes it has already stood on.
struct Walk {
  const KonstAnswers& answers;
  bool* seen;
};

// c4 counts as one, for the reason walk() gives above.
constexpr bool reaches_a_node_that_reads_the_request(Node n, Walk w) {
  const KonstAnswers& k = w.answers;
  bool* const seen = w.seen;
  if (seen[static_cast<size_t>(n)]) return false;
  seen[static_cast<size_t>(n)] = true;
  const FlowNode& f = kFlow[static_cast<size_t>(n)];
  if (f.kind == Kind::kRequest || n == Node::kC4) return true;
  const Target& t = k.ans[static_cast<size_t>(n)] ? f.on_true : f.on_false;
  if (t.status != 0) return false;
  return reaches_a_node_that_reads_the_request(t.node, w);
}

// The two skips above are claims about the graph, so the graph is asked.
// From `from`, with the block's fields absent, follow the edges the way walk
// does and report where it comes out. kNodeCount is the give-up bound: a
// halt or a wrong exit both fail the assert below.
// The request as parsed, and what the fold decided for this resource.
struct Given {
  const ReqFacts& req;
  const KonstAnswers& konst;
};

constexpr Node lands_on(Node from, Given g) {
  const ReqFacts& req = g.req;
  const KonstAnswers& k = g.konst;
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
  return lands_on(Node::kC3, {absent, all_false}) == kAfterConneg &&
         lands_on(Node::kC3, {absent, all_true}) == kAfterConneg &&
         lands_on(Node::kG8, {absent, all_false}) == kAfterConditional &&
         lands_on(Node::kG8, {absent, all_true}) == kAfterConditional;
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
  s.always = !reaches_a_node_that_reads_the_request(Node::kB13, {k, seen});
  return s;
}

// What the fold settled about one resource, for one method: the konst
// answers the walk follows, and the shortcut that says when it need not
// walk at all.
struct Decided {
  const KonstAnswers& konst;
  const Shortcut& shortcut;
};

// RFC 9110: the one entry point the request path calls. Two integer tests
// where the graph could not have said anything else.
constexpr uint16_t answer(const ReqFacts& req, Decided d) {
  if (d.shortcut.always || (req.plain && !req.has_accept)) return d.shortcut.status;
  return walk(req, d.konst);
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

// The three classes this library refuses with. Defined here, above the
// first raise, because since #33 a refusal IS one of these.
#define E_WM_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Error)))
#define E_WM_CONFIG_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(ConfigError)))
#define E_WM_ROUTE_ERROR(mrb) \
  (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(RouteError)))

namespace webmachine {

// mruby's GC arena is a stack, and a setup that gives up has to leave it
// where it found it. Since #33 those exits are raises - a raise is a C++
// throw here, MRB_USE_CXX_EXCEPTION is always on - so the restore belongs
// to a destructor, not to fifteen copies of the same line before fifteen
// returns, each of which was a chance to forget one.
// A setup callback raised and the VM left the exception in mrb->exc
// (mrb_funcall_argv catches it there; mrb_protect_error hands it back and
// take_pending puts it there). Let it out again: the exception's own
// class, message and backtrace name what went wrong better than any
// sentence the frame that caught it could spell - and since #33 there is
// no string channel left to spell one into. What this replaced printed
// the exception to stderr, which nothing reads unless the process dies,
// and passed "<callback> (exception below)" upwards: a note about a note.
// The same, for what mrb_protect_error hands BACK rather than leaves in
// mrb->exc. Only an exception object can be raised, and protect_error
// returns whatever was pending - the trap take_pending is about.
[[noreturn]] inline void reraise(mrb_state* mrb, mrb_value pending) {
  if (mrb_exception_p(pending)) mrb_exc_raise(mrb, pending);
  mrb_raisef(mrb, E_WM_ERROR(mrb), "a protected call ended with %v and no exception", pending);
}

[[noreturn]] inline void rethrow(mrb_state* mrb) {
  const mrb_value exc = mrb_obj_value(mrb->exc);
  mrb->exc = nullptr;
  reraise(mrb, exc);
}

class ArenaGuard {
 public:
  explicit ArenaGuard(mrb_state* mrb) : mrb_(mrb), at_(mrb_gc_arena_save(mrb)) {}
  ~ArenaGuard() { mrb_gc_arena_restore(mrb_, at_); }
  ArenaGuard(const ArenaGuard&) = delete;
  ArenaGuard& operator=(const ArenaGuard&) = delete;

 private:
  mrb_state* const mrb_;
  const int at_;
};

// How many segments of a path one route may bind. It is mruby's own
// number: vm.c holds a mrb_funcall's arguments in mrb_value
// argv[MRB_FUNCALL_ARGC_MAX] and raises above it rather than growing a
// buffer, which is this array's shape exactly. mrbconf.h declares the
// knob but nothing defines it unless a build does, so the fallback here
// is vm.c's own - and a build that lowers the VM's number lowers this
// one with it, because the two are the same decision.
//
// The refusal moves EARLIER than mruby can move it: a mrb_funcall is
// only known when it happens, while a route is known when the app
// registers it, so binding() refuses the one Symbol past the limit at
// add_route and the match loop never tests anything.
#ifdef MRB_FUNCALL_ARGC_MAX
inline constexpr size_t kMaxRouteBindings = MRB_FUNCALL_ARGC_MAX;
#else
inline constexpr size_t kMaxRouteBindings = 16;
#endif

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
    // What the caller may read whatever this returns. The spans behind
    // them are written only as far as nbind and has_splat admit, which
    // is what lets RouteSpans stay uninitialized at the top of a
    // request path.
    out.nbind = 0;
    out.has_splat = false;
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

// route.add: a route is open from its first token until it stands. Every
// other way out of that window - a token that is not a segment, a class
// the fold refuses - leaves NOTHING registered, and since #33 every one
// of those ways out is a raise.
class OpenRoute {
 public:
  explicit OpenRoute(RouteTable& table) : table_(table) { table_.open(); }
  ~OpenRoute() {
    if (!stands_) table_.abandon();
  }
  OpenRoute(const OpenRoute&) = delete;
  OpenRoute& operator=(const OpenRoute&) = delete;
  // The route stands: there is nothing left to roll back.
  void commit() {
    table_.commit();
    stands_ = true;
  }

 private:
  RouteTable& table_;
  bool stands_ = false;
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

// One row of the password database, shared by webmachine-passwd, which
// writes it, and the server, which verifies against it.
//
// The format is ours, and it exists for one reason: argon2's own encoded
// form ($argon2id$v=19$m=...,t=...,p=...$salt$hash) cannot carry the ad
// parameter. argon2id_hash_encoded takes a password, a salt and the
// three costs and nothing else; ad needs the context API, and that hands
// back a raw hash. So salt and cost are written here instead of read out
// of a string.
//
// ad is the sub-database's NAME, and it is NOT stored. Both sides
// already hold it - the tool from its argument, the server from the
// route that named it - and a record therefore verifies only in the set
// it was made for. Copying a row from one sub-database to another leaves
// it unverifiable.
//
// Native widths and native order. That is not a shortcut: LMDB refuses a
// file written by a different endianness or word size, so a record can
// never outlive the constraint the database is already under.
struct PasswdRec {
  uint8_t version;
  uint8_t salt_len;
  uint8_t hash_len;
  uint8_t lanes;   // argon2's p
  uint32_t m_kib;  // argon2's m, in KiB
  uint32_t t;      // argon2's t
  // When this user was first written, and when their password last
  // changed. Seconds, the clock's, and they answer the questions an
  // operator actually asks of a user list: who is new, and who has not
  // changed a password since the cost was raised. A record whose m_kib
  // is below what the machine now uses and whose mtime is old is
  // exactly the row to ask about.
  int64_t ctime;
  int64_t mtime;
  // salt_len bytes of salt follow, then hash_len bytes of hash.
};
inline constexpr uint8_t kPasswdRecVersion = 1;

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

// WHEN a body is worth lending instead of copying.
//
// A lend saves the copy and costs a segment: the head is in the sink and
// the body is somewhere else, so the answer leaves as sendmsg with an
// iovec instead of send with one pointer. Two profiles of the same h1
// run say what that costs. Before the lend: io_send 2.26%, import_ubuf
// 0.27%, io_send_setup 0.14%. After it: io_msg_copy_hdr 1.68,
// copy_iovec_from_user 1.39, ____sys_sendmsg 1.42, __import_iovec 0.81,
// io_net_import_vec 0.72, iovec_from_user 0.50, __copy_msghdr 0.13, plus
// io_sendmsg_prep and io_sendmsg_setup. Five points of one core.
//
// examples/hello.rb has a 39-byte body. The copy it saves is nothing.
// So a small body is copied, as it was, and a big one is lent - which is
// the case the lend was written for: 300 stalled readers of a 64 KB
// answer held 19.5 MB of duplicates.
//
// The number is a break-even and belongs to the machine that runs it.
// bench/floor.sh moves it, not an argument.
inline constexpr size_t kLendFloor = 4096;

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

// A raise inside a worker VM, written by the reactor. The exception
// object itself cannot cross - an mrb_value belongs to the VM that made
// it - so the worker spells it out as text and these are its words. The
// worker's thread name goes into the message, because a fault that says
// what broke and not WHERE it ran sends the reader to the wrong core.
struct ComputeFault {
  std::string_view exception_class;
  std::string_view message;
  std::string_view backtrace;
  std::string_view worker_name;
  std::string_view peer;
  std::string_view request_target;
};

inline void log_compute_fault(Logger& lg, const ComputeFault& x) {
  if (!lg.enabled) return;
  std::string message;
  message.reserve(x.message.size() + x.worker_name.size() + 4);
  message.append(x.message);
  if (!x.worker_name.empty()) {
    if (!message.empty()) message.append(" ");
    message.append("(").append(x.worker_name).append(")");
  }
  ErrFacts f;
  f.peer = x.peer.data();
  f.peer_len = x.peer.size();
  f.request_target = x.request_target.data();
  f.request_target_len = x.request_target.size();
  f.exception_class = x.exception_class.data();
  f.exception_class_len = x.exception_class.size();
  f.message = message.data();
  f.message_len = message.size();
  f.backtrace = x.backtrace.data();
  f.backtrace_len = x.backtrace.size();
  // A compute task that raised answers nothing, and 500 is what the run
  // sends. The record says the same number the client got.
  f.status_code = 500;
  log_error(lg, f);
}

// A condition the server hit with nobody to answer for it: no request, no
// peer, no status. The error log is where it belongs and it goes there
// whole. stderr gets it only when no error log was configured, because
// then there is nothing else to read - a line printed beside a log that
// IS being read is a line nobody reads.
inline void say_server_error(Logger* lg, std::string_view why) {
  if (lg != nullptr && lg->enabled) {
    log_internal_error(*lg, {{}, {}, why, 0});
    return;
  }
  std::fprintf(stderr, "webmachine: %.*s\n", static_cast<int>(why.size()), why.data());
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
// What one raise leaves behind: the record's fields, and the backtrace
// text they point into.
struct Raised {
  ErrFacts& facts;
  std::string& backtrace;
};
void exception_facts(mrb_state* mrb, Raised out);

// A raise with no request around it: a stream that was answered long ago
// and is now running app code of its own (SSE, a WebSocket). There is no
// target and no method to name, so the fingerprint is the build, the
// class and the place - which is exactly what such a failure is.
inline void log_raise(Logger& lg, mrb_state* mrb, uint16_t status) {
  if (!lg.enabled) return;
  ErrFacts f;
  std::string backtrace;
  f.status_code = status;
  exception_facts(mrb, {f, backtrace});
  if (f.exception_class == nullptr) return;
  log_error(lg, f);
}
}

namespace webmachine::http {
// RFC 9110 5.1: case-insensitive equality against a lowercase literal.
constexpr bool tok_eq(std::string_view text, std::string_view lit) {
  const char* const s = text.data();
  const size_t n = text.size();
  if (n != lit.size()) return false;
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
  if (type.size() < 5 || !tok_eq({type.data(), 5}, "text/")) return type;
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
  if (tn >= 5 && tok_eq({v, 5}, "text/")) return true;
  if (tn >= 5 && tok_eq({v + tn - 5, 5}, "+json")) return true;
  if (tn >= 4 && tok_eq({v + tn - 4, 4}, "+xml")) return true;
  constexpr const char* kExact[] = {
      "application/json", "application/javascript", "application/xml",
      "application/wasm", "image/svg+xml",
  };
  for (const char* lit : kExact) {
    if (tok_eq({v, tn}, lit)) return true;
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
inline ClStatus parse_content_length(std::string_view v, size_t* out) {
  const char* const s = v.data();
  const size_t n = v.size();
  if (n == 0) return ClStatus::kBad;
  size_t acc = 0;
  for (size_t j = 0; j < n; j++) {
    const char ch = s[j];
    if (ch < '0' || ch > '9') return ClStatus::kBad;
    size_t t = 0;
    if (__builtin_mul_overflow(acc, static_cast<size_t>(10), &t) ||
        __builtin_add_overflow(t, static_cast<size_t>(ch - '0'), &acc)) {
      return ClStatus::kOverflow;
    }
  }
  *out = acc;
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

// The parsed field array and how many fields it holds - the pair every
// stored position is only meaningful against.
struct HeaderList {
  const struct phr_header* items;
  size_t count;
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
  const struct phr_header* find(NamedField f, HeaderList hs) const;

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

// #80: every pointer in ReqValues, in ONE place. A parked run has to
// rebase all of them onto bytes it owns, and rebasing eleven of twelve
// is a dangling pointer that only bites the run that stopped - which is
// the rarest path there is, so it would be found in production and not
// here. Written as member pointers rather than as twelve assignments so
// there is one list to be right about.
//
// The size assert is the whole guard: a field added to the struct above
// changes it, and the build stops until the field is listed here too. It
// fixes nothing else - what a byte MEANS is not this list's business.
inline constexpr const char* ReqValues::*kReqValueSpans[] = {
    &ReqValues::log_ref,       &ReqValues::log_ua,        &ReqValues::accept_encoding,
    &ReqValues::if_match,      &ReqValues::if_none_match, &ReqValues::range,
    &ReqValues::if_range,      &ReqValues::authorization, &ReqValues::content_type,
    &ReqValues::accept,        &ReqValues::host,          &ReqValues::cookie,
};
static_assert(sizeof(ReqValues) == 224,
              "ReqValues changed shape: a new field belongs in kReqValueSpans, and a "
              "removed one has to leave it - see #80, the parked run's rebase");

// Move every span in `v` by `delta`. A null span stays null: it names no
// bytes, so there is nothing to move and an offset from nullptr is
// undefined besides.
inline void rebase(ReqValues& v, ptrdiff_t delta) {
  for (const char* ReqValues::*m : kReqValueSpans) {
    if (v.*m != nullptr) v.*m += delta;
  }
}

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
// The Range field's value, and the length of the representation it is
// measured against.
struct RangeField {
  std::string_view value;
  size_t complete;
};

// The one range it named, inclusive at both ends.
struct ByteRange {
  size_t first;
  size_t last;
};

inline RangeParse parse_range(RangeField field, ByteRange& out) {
  const char* const v = field.value.data();
  const size_t n = field.value.size();
  const size_t complete = field.complete;
  size_t* const first = &out.first;
  size_t* const last = &out.last;
  if (n < 7 || !tok_eq({v, 6}, "bytes=")) return RangeParse::kNone;
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
inline bool if_range_matches(std::string_view v, std::string_view tag) {
  const char* const p = v.data();
  const size_t n = v.size();
  const size_t taglen = tag.size();
  size_t i = 0;
  while (i < n && (p[i] == ' ' || p[i] == '\t')) i++;
  size_t e = n;
  while (e > i && (p[e - 1] == ' ' || p[e - 1] == '\t')) e--;
  return e - i == taglen && std::memcmp(p + i, tag.data(), taglen) == 0;
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
      if (tok_eq({v + ts, tl}, "gzip") || tok_eq({v + ts, tl}, "x-gzip")) {
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

// RFC 9110 13.1.1/13.1.2: the field's list of entity-tags, the selected
// representation's own tag, and which comparison applies - strong for
// If-Match, weak for If-None-Match.
struct EtagMatch {
  std::string_view list;
  std::string_view tag;
  bool weak;
};

inline bool etag_list_match(EtagMatch m) {
  const char* const v = m.list.data();
  const size_t n = m.list.size();
  const char* const tag = m.tag.data();
  const size_t taglen = m.tag.size();
  const bool weak = m.weak;
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
// One civil date and time, as the fields a Date line spells.
struct Civil {
  int y;
  int m;
  int d;
  int hh;
  int mm;
  int ss;
};

inline int64_t epoch_from_civil(Civil c) {
  int y = c.y;
  const int m = c.m, d = c.d, hh = c.hh, mm = c.mm, ss = c.ss;
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
  *out = epoch_from_civil({y, mo, d, hh, mm, ss});
  return true;
}

// RFC 9110 12.5.1: choose among the provided types given an Accept
// value - q-values and both wildcard forms, most specific match per
// type, highest q wins, the provided ORDER breaks ties (webmachine
// conneg semantics). -1 = nothing acceptable (406). `types` may carry
// parameters; matching reads only the type/subtype half.
// RFC 9110 12.5.1: the media types this resource provides, and the Accept
// the request sent.
struct Conneg {
  std::span<const std::string> provided;
  std::string_view accept;
};

// RFC 9110 12.5.1: an exact type/subtype is the most specific match a
// range can be, so a first range that IS the offered type answers the
// whole question - no q ordering to do, nothing later that can outrank
// it. One memcmp of the type's own length, whatever the client sent
// after it: htmx 4's `text/html` and a browser's
// `text/html,application/xhtml+xml,...,*/*;q=0.8` cost the same here.
//
// Deliberately narrow. A parameter (`;q=`, `;charset=`) on that first
// range, or a case that does not match byte for byte, falls back to
// choose_media_type, which is case-insensitive and weighs q properly.
// This answers the common shape in constant time and refuses to guess
// about any other.
inline bool accept_is_exact(std::string_view accept, std::string_view type) {
  const char* const a = accept.data();
  const size_t n = accept.size();
  size_t i = 0;
  while (i < n && (a[i] == ' ' || a[i] == '\t')) i++;
  if (n - i < type.size()) return false;
  if (std::memcmp(a + i, type.data(), type.size()) != 0) return false;
  i += type.size();
  while (i < n && (a[i] == ' ' || a[i] == '\t')) i++;
  return i == n || a[i] == ',';
}

inline int choose_media_type(Conneg c) {
  const std::string* const types = c.provided.data();
  const size_t ntypes = c.provided.size();
  const char* const av = c.accept.data();
  const size_t alen = c.accept.size();
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
      } else if (!tok_eq({rg.t, rg.tn}, {tp, main_n})) {
        continue;
      } else if (rg.sn == 1 && rg.sub[0] == '*') {
        this_spec = 1;
      } else if (tok_eq({rg.sub, rg.sn}, {sub_p, sub_n})) {
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

// RFC 3986 5.3: a reference and the base it is resolved against.
struct UriRef {
  std::string_view base;
  std::string_view ref;
};

// The n11 subset: join create_path onto a base. A full URI passes
// verbatim; an absolute-path ref replaces the base's path; a relative
// segment appends after the base's last '/'.
inline void uri_join(UriRef r, std::string& out) {
  const char* const base = r.base.data();
  const size_t blen = r.base.size();
  const char* const path = r.ref.data();
  const size_t payload_length = r.ref.size();
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

// One header field as it lies in the head: its name and its value.
struct Field {
  std::string_view name;
  std::string_view value;
};

// Where one request's parsed facts are being filled: the facts themselves,
// the values that point back into the head, and the index of the field
// being read - a value's own position is how the framer finds it again.
struct FactSink {
  flow::ReqFacts& facts;
  ReqValues& vals;
  size_t at;
};

// RFC 9110: ONE length-switch per header. The 9110 facts are filled here;
// true means the name is not one of them and the framer must read it.
static inline bool header_switch(Field f, FactSink into) {
  const char* const name = f.name.data();
  const size_t nlen = f.name.size();
  const char* const value = f.value.data();
  const size_t vlen = f.value.size();
  flow::ReqFacts& facts = into.facts;
  ReqValues& vals = into.vals;
  const size_t at = into.at;
  if (!length_is_one_of(nlen, kFieldLengthMask)) return true;
  switch (nlen) {
    case 3:
      if (tok_eq({name, nlen}, "dnt")) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return false;
      }
      break;
    case 4:
      if (tok_eq({name, nlen}, "host")) {
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
      if (tok_eq({name, nlen}, "range")) {
        vals.range = value;
        vals.range_len = vlen;
        return false;
      }
      break;
    case 6:
      if (tok_eq({name, nlen}, "accept")) {
        // NOT plain = false: has_accept is asked separately by answer(),
        // so the request path can clear it when the Accept turns out to
        // name exactly what the route offers - a negotiation with one
        // outcome, back on the shortcut. Everything else that clears
        // plain stays as it is.
        facts.has_accept = true;
        vals.accept = value;
        vals.accept_len = vlen;
        vals.named.note(NamedField::kAccept, at);
        return false;
      }
      if (tok_eq({name, nlen}, "cookie")) {
        vals.cookie = value;
        vals.cookie_len = vlen;
        return false;
      }
      break;
    case 7:
      if (tok_eq({name, nlen}, "sec-gpc")) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return false;
      }
      break;
    case 8:
      if (tok_eq({name, nlen}, "if-range")) {
        vals.if_range = value;
        vals.if_range_len = vlen;
        return false;
      }
      if (tok_eq({name, nlen}, "if-match")) {
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
      if (tok_eq({name, nlen}, "content-type")) {
        // RFC 9110 8.3: b5's argument and accept_helper's key.
        vals.content_type = value;
        vals.content_type_len = vlen;
        vals.named.note(NamedField::kContentType, at);
        return false;
      }
      break;
    case 13:
      if (tok_eq({name, nlen}, "authorization")) {
        // RFC 9110 11.6.2: b8's argument.
        vals.authorization = value;
        vals.authorization_len = vlen;
        vals.named.note(NamedField::kAuthorization, at);
        return false;
      }
      if (tok_eq({name, nlen}, "if-none-match")) {
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
      if (tok_eq({name, nlen}, "accept-charset")) {
        facts.has_accept_charset = true;
        facts.plain = false;
        return false;
      }
      break;
    case 15:
      if (tok_eq({name, nlen}, "accept-language")) {
        facts.has_accept_language = true;
        facts.plain = false;
        return false;
      }
      if (tok_eq({name, nlen}, "accept-encoding")) {
        facts.has_accept_encoding = true;
        facts.plain = false;
        vals.accept_encoding = value;
        vals.accept_encoding_len = vlen;
        vals.named.note(NamedField::kAcceptEncoding, at);
        return false;
      }
      break;
    case 17:
      if (tok_eq({name, nlen}, "if-modified-since")) {
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
      if (tok_eq({name, nlen}, "if-unmodified-since")) {
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
  // LENT, not carried: the match loop's own RouteSpans lives in the
  // frame that matched, which is the frame this view is read from - so
  // pointing at it costs one store where a copy cost 280 bytes, most of
  // them past nbind and unreadable by contract. nullptr where nothing
  // matched, and the accessors say so.
  const RouteSpans* spans = nullptr;
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
void values_of_copied_fields(http::HeaderList h, http::ReqValues& out);

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
// One native callback to register: the name Ruby calls it by, the C++ body
// the engine calls instead, and the argument spec the wrapper declares.
struct Native {
  mrb_sym sym;
  NativeCb fn;
  mrb_aspec aspec = MRB_ARGS_ANY();
};
void define_native(mrb_state* mrb, struct RClass* c, Native n);

// #210: a run may hand over one of these (response.error_asset). The
// definition is further down, with the tier that owns it - a run only
// ever passes the handle on.
struct AssetEntry;

// #30: how many watchers one connection may run. It is what fits in the
// tag's spare byte, and 256 is far past anything a connection has reason
// to hold.
inline constexpr unsigned kMaxWatchers = 256;

// #30: how many jobs one stop can hand over. A node's own callback is
// one. A value round asks for an ETag, a Last-Modified, an Expires and
// a body, and the flow lets all four run at the same time - none of
// them chooses an edge.
inline constexpr int kValueJobs = 4;
// What a job answers. kJobNode is a node's own callback, and it is
// alone in its round.
enum : uint8_t { kJobNode = 0, kJobEtag = 1, kJobLastModified = 2, kJobExpires = 3 };

struct Resource {

  flow::KonstSet konst;
  mrb_state* mrb = nullptr;
  struct RClass* klass = nullptr;
  // The class's own class - where a `def self.x` lives. Kept because
  // entering such a method directly needs the class it was found in, and
  // the fold freezes klass, so this pointer is as stable as klass itself.
  struct RClass* meta_klass = nullptr;
  uint64_t dynamic = 0;
  // #80: one bit per node whose callback a worker answers. A subset of
  // `dynamic` - only a node the VM decides can be promised at all - and
  // read in the same load, so a run knows before it enters the VM
  // whether this node can stop. Zero for every resource that never says
  // `compute`, which is what keeps the pool out of a server that has no
  // use for it.
  uint64_t compute = 0;
  // #30: which nodes answer with a Webmachine::Watcher. Declared with
  // `watch :is_authorized?`, the same shape as `compute` and for the
  // same reason: the frame that can hold a stopped run is chosen before
  // any callback runs, so the resource has to say so in advance.
  //
  // Unlike a compute task, the block here is never dumped - it runs in
  // this VM, on this thread - so it may keep its environment and the
  // callback may live on the instance.
  uint64_t watch = 0;
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

  // #80: EVERYTHING one request writes on the way through, in one
  // place. It used to be thirty-one `mutable` members on Resource, and
  // that was right while a run could not stop: only one ran at a time.
  // A run that PARKS breaks it - the next request on the same route
  // writes these while the parked one still needs them. So the parked
  // run takes the whole struct with it and gives it back on the way in.
  // One move each way, and no hand-written member list that can be
  // short by one - the same argument Held is built on.
  struct RunState {
    mrb_value live = {};
    // #80: where the walk stands. A run that parks returns out of the
    // node loop, and these three are what it re-enters with - the node
    // it stopped BEFORE, the status it had collected, and the media type
    // conneg had settled on. Nothing of a Ruby stack is here, because
    // the stop is between callbacks and never inside one.
    flow::Node stop_node = flow::Node::kB13;
    uint16_t stop_status = 0;
    int chosen = 0;
    // May this run stop at all? The konst tier and the error resource
    // say no: they are not called through a frame that could hold a
    // parked run, and a stop with nobody to resume it is a hang.
    bool can_park = false;
    // It stopped, and the reactor has the job now.
    bool stopped = false;
    // The worker answered, and the answer is `answer`. The node the run
    // re-enters reads this INSTEAD of calling its callback - that is the
    // whole of "the graph carries on from B8".
    bool answered = false;
    mrb_value answer = {};
    // #80: what the stopped run owes a worker - which block, and the
    // arguments this request built for it. The arguments are an Array
    // in this VM until the reactor turns them into CBOR.
    // The block itself, until the reactor interns it. It is a value of
    // THIS VM, so it never leaves this struct - what leaves is the id
    // the intern answers with.
    struct HeldTask {
      mrb_value block = {};
      mrb_value args = {};
      double deadline = 0.0;
      // Which answer this task is: a node's own callback, or one of the
      // values a round asks for at the same time.
      uint8_t what = 0;
    };
    HeldTask compute_task[kValueJobs];
    // How many tasks this stop holds. One for a node's own callback.
    uint8_t compute_task_count = 0;
    // #30: the Watcher this run stopped on. A value of THIS VM, held
    // until the frame hands it to the connection - the connection's hash
    // is what roots it while the run waits.
    // #30: what the application itself carries from one callback to the
    // next. A Hash, made when a callback first asks for it, and let go
    // when the run ends. The run frame is its whole life - a value put
    // here in generate_etag is there in to_html, and it is gone before
    // the next request on this connection.
    // #30: `response.userdata` - one slot the application carries from
    // one callback of this run to the next. Undef until something is
    // put there, so a run that never uses it allocates nothing and
    // Ruby never sees the undef. The server never reads what is in it.
    mrb_value userdata = {};
    bool userdata_held = false;
    mrb_value watch[kValueJobs] = {};
    uint8_t watch_what[kValueJobs] = {};
    uint8_t watch_count = 0;
    // #30: the value round started. It starts once per run, at the
    // first node that needs any of its answers.
    bool values_started = false;
    const flow::ReqFacts* facts = nullptr;
    std::string* body = nullptr;
    bool have_body = false;
    // #210 response.error_asset: THE ENTRY, not its bytes. The error assets
    // are mmap'd for the life of the process, and both writers already know
    // how to put a mapped entry on the wire - Assets::wire_len/wire_iov/
    // copy_wire on h1, Content::Src::kAsset on h2 - so this run hands over
    // the same handle the asset tier hands over, and nothing is rooted,
    // copied or released for it.
    const AssetEntry* asset = nullptr;
    uint16_t status = 0;
    // Zero-copy hand-off: at or above run_zc_min bytes the body handler's
    // own String is frozen and rooted and LENT to the writer, instead of
    // being copied into run_body. 0 = never lend, which is every caller
    // that does not pass a threshold.
    size_t zc_min = 0;
    mrb_value zc = {};
    bool zc_have = false;

    // Per-request slots for the RUNTIME tier, all reset by resource_run
    // at frame entry. `run_headers` takes the field lines this request
    // produced; the writer appends it between the prebuilt head and
    // Content-Length, which is exactly where the prebuilt head stops, so
    // no prebuilt byte moves.
    std::string* headers = nullptr;
    const http::ReqValues* vals = nullptr;
    const ReqView* req = nullptr;
    // response.code= / response.do_redirect (response.cpp writes these;
    // the flow's halt seeds run_resp_code, finish_request may change it
    // - fsm.rb's respond order).
    uint16_t resp_code = 0;
    bool redirect = false;
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
    std::string content_type;
    // n11: create_path's override of request.disp_path.
    std::string disp_path;
    bool disp_set = false;
    // response.file = "rel/path": the NAME only. Nothing is opened here - the
    // reactor does that through the ring, so a callback never blocks on a
    // disk. run_file_bad is a name this process refused before the kernel saw
    // it (empty, embedded NUL); it answers 404 in the SAME shape a rejected
    // resolve does, so neither is distinguishable from a plain miss.
    std::string file;
    bool have_file = false;
    bool file_bad = false;

    // Once-per-run memos: generate_etag / last_modified / expires are
    // asked at most ONCE (g11+k13+o18 share etag; h12+l17+o18 share
    // last_modified), whatever the graph visits.
    bool etag_asked = false;
    bool etag_present = false;
    std::string etag_value;  // spelled, quoted form
    bool last_modified_asked = false;
    bool last_modified_present = false;
    int64_t last_modified_epoch = 0;
    bool expires_asked = false;
    bool expires_present = false;
    int64_t expires_epoch = 0;
    // Marshalled once per run where the app answered dynamically;
    // capacity survives across requests.
    // The dynamic content_types_provided, marshalled from the app's Array.
    // It SURVIVES the run on purpose: the handler's method is resolved here,
    // and re-resolving it per request is a method search per request on the
    // path that renders every body. marshal_ct compares the app's fresh
    // answer against this and only rebuilds when it actually differs - which
    // for every resource that answers the same list each time is never.
    std::vector<TypedHandler> content_types_provided;
    bool content_types_marshalled = false;
    std::vector<std::string> methods;
    std::vector<std::string> variances;
  };
  mutable RunState run;
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
  // #30: which values a round asks a worker for, one bit per kJob*.
  // The flow never lets one of them choose an edge, so all of them can
  // be out at the same time.
  uint8_t value_jobs = 0;
  // #30: the same, for values a WATCHER answers. A descriptor says when
  // the value is there; the flow reads it in the same places.
  uint8_t value_watch = 0;
  bool has_caching = false;
};

void resource_fold(mrb_state* mrb, mrb_value klass, Resource& out);

// One request as a bound run receives it: what the parse settled, the
// header values the calling frame still holds (none where that frame is
// already gone), the bytes themselves, and the smallest body worth LENDING
// rather than copying - 0 where nothing downstream could hold a lend.
struct RunAsk {
  const flow::ReqFacts& facts;
  const http::ReqValues* vals;
  const ReqView* req;
  size_t zc_min = 0;
  // #80: may this run stop at a promised node? Only a caller that holds
  // a frame able to keep the parked run says yes. The konst tier and the
  // error resource say no, and then `compute` costs one branch and
  // changes nothing else.
  bool can_park = false;
};

// Where a bound run writes what it produced: the body it spelled, whether
// it spelled one at all, and the field lines it named.
struct RunAnswer {
  std::string* body;
  bool* have_body;
  std::string* headers;
};

// The walk, once. It answers a status, or it STOPPED: `run_stopped`
// says which, and the job the reactor owes a worker is read with
// `resource_job`. A stopped run keeps everything it wrote in res.run,
// which the caller takes with it.
uint16_t resource_run(const Resource& res, RunAsk ask, RunAnswer out);
// #80: the same walk, re-entered at the node it stopped before, with the
// worker's answer standing in for that node's callback.
// #30: what a round answered. One entry per job: the value, and which
// answer it is (kJob*). A node's own callback is one entry of kJobNode.
struct RunRound {
  const mrb_value* answers;
  const uint8_t* what;
  // #30: response.userdata a worker changed, per job, or nothing.
  const mrb_value* user;
  const bool* user_have;
  uint8_t n;
};
uint16_t resource_resume(const Resource& res, RunAnswer out, const RunRound& round);
bool run_stopped(const Resource& res);

bool resource_exception_take(const Resource& res, mrb_value* out);

// The body a bound run LENT rather than copied: the value the connection
// has to hold until its send drains, and the bytes it may point at.
// What a run LENT: the value the connection has to hold until its send
// drains, and the bytes it may point at.
struct LentBody {
  mrb_value value;
  std::string_view bytes;
};
bool resource_body_lent(const Resource& res, LentBody& out);

// Hand a lent body back - the only legal end of the window opened above.
void resource_body_unlend(mrb_state* mrb, mrb_value v);

// Did this run name a file instead of spelling a body? Same hand-off shape
// as resource_body_lent: the run is over, so the slot leaves the Resource.
// The file a run named, and whether the name was one this server refuses
// to open at all.
struct WantedFile {
  std::string_view name;
  bool bad;
};
bool resource_file_wanted(const Resource& res, WantedFile& out);

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

// #80: the compute pool. Threads that answer a compute task, fed and heard
// through io_uring's own MSG_RING - see src/compute_task.cpp for why that is
// the queue and not a ring buffer of this tree's own.
//
// It holds no mrb_state and touches none: a job is a C function over
// bytes, because the VM is not thread-safe and work that wanted it would
// be work for the reactor's core.
// #80: what a declared callback RETURNS. Webmachine::ComputeTask,
// built on the reactor by a callback that only builds it:
//
//   compute :is_authorized?
//   def self.is_authorized?(header)
//     Webmachine::ComputeTask.new(header, max_runtime: 50.ms) do |h|
//       argon2_verify(h)
//     end
//   end
//
// The method is fast and runs where every other callback runs. What
// goes to a worker is the BLOCK, with its own arguments and its own
// deadline - so the stop still lies between two flow nodes, and no
// Ruby method is ever suspended mid-run.
//
// A callback that is declared `compute` and answers anything else is a
// mistake this tree names rather than guesses at.
struct ComputeTaskAsk {
  // The block, and the arguments it is called with. Both belong to the
  // reactor's VM; the crossing turns them into bytes.
  mrb_value block = {};
  mrb_value args = {};
  // Seconds. mruby-chrono spells it: 50.ms is 0.05.
  double max_runtime = 0.0;
};
// Reads the three fields off a Promise, or answers false. It raises
// when the value is not a Promise at all, because a callback that
// declared one owes one.
bool compute_task_of(mrb_state* mrb, mrb_value v, ComputeTaskAsk* out);
void compute_task_init_class(mrb_state* mrb, struct RClass* wm);

// #80: a declared callback, ready to cross into a worker. Filled at
// fold, read by every worker when the pool starts. The id IS the index -
// what crosses a MSG_RING is a slot number, and the slot names this.
//
// Exactly one of the two is set. A Ruby callback travels as its dumped
// irep, which every worker loads once. A native one travels as nothing
// at all: the pointer is the same number in every VM of this process.
struct ComputeTaskCode {
  // The block, dumped once. A worker loads it once and calls it many
  // times.
  std::string irep;
  // Seconds, from max_runtime:. Admission is arithmetic over this, and
  // a worker ends a Task that runs past it. It comes from the same
  // Promise the block came from, so it is read once as well.
  double max_runtime = 0.0;
};
// #80: what a worker keeps between jobs. A block carries no
// environment, so it cannot hold a database or a connection - and
// opening one per request would cost more than the work it exists for.
//
// So the application registers HOW TO BUILD one, and every worker runs
// that once when it opens its VM:
//
//   Webmachine::Workers::Registry[:db] = proc { MDB::Env.new(path) }
//
// and a block reads back its OWN worker's value under the same key. No
// lock anywhere: nothing is shared, because each worker built its own.
//
// The key crosses as a STRING, not as a symbol. An mrb_sym is a number
// one VM handed out, and it means nothing in another.
struct WorkerBuild {
  std::string key;
  std::string irep;
};
// Registered from the main VM at startup. Answers false when the pool
// has already started - a key set then exists in no worker.
bool worker_build_register(mrb_state* mrb, std::string key, mrb_value block);
const std::vector<WorkerBuild>& worker_builds();
// Said once, when the first worker starts. After it a registration is
// refused rather than silently missing from every worker.
void worker_builds_close();

// No block: the dump refused, which only a proc that mruby cannot dump
// does. A run that gets this answers as if the pool were full.
inline constexpr unsigned kComputeTaskNoCode = ~0u;

// The id of this block, dumping it the first time it is seen.
//
// NOT at fold: the class method that answers the Promise builds its
// arguments out of the request, and add_route has no request. So the
// first request through the node pays one dump (0.63 us, measured) and
// every request after it pays a lookup - the same code at the same
// place carries the same irep, whatever RProc is built around it.
unsigned compute_task_intern(mrb_state* mrb, mrb_value block, double max_runtime);
// The bytes and the deadline of one entry, copied out under the lock.
// A worker calls this the first time it meets an id, and never again
// for that id.
bool compute_task_code_of(unsigned id, std::string* irep, double* max_runtime);

// How many workers this build may ever run: MRB_TASK_MAX_VMS less the
// reactor's own VM. The number is mruby-task's, and it counts VMs over
// the whole PROCESS - a worker that cannot register its VM answers
// nothing, so asking here is not a preference, it is the ceiling.
// Defined in compute_task.cpp, which is where mruby-task's header is.
unsigned compute_worker_ceiling();

// What one job left behind. The bytes are the answer; the rest is what
// the reactor needs to write a failure down, because a worker cannot -
// the error log belongs to the reactor's thread.
struct ComputeAnswer {
  std::string bytes;  // the answer as CBOR, empty when the job raised
  // #30: response.userdata on the way back, when the worker changed it.
  // Same bytes as on the way out otherwise, and then nobody looks.
  std::string user_bytes;
  bool user_changed = false;
  bool raised = false;
  // The task ran past its max_runtime and the worker ended it. Not a
  // raise: the author's number was wrong, and a retry costs the same
  // (.DESIGN.md #promise-bound).
  bool over_deadline = false;
  std::string exception_class;
  std::string message;
  std::string backtrace;
  // The thread that ran it, as the name a backtrace shows.
  std::string worker_name;
};

class ComputePool {
 public:

  ComputePool() = default;
  ~ComputePool() { stop(); }
  ComputePool(const ComputePool&) = delete;
  ComputePool& operator=(const ComputePool&) = delete;

  // nullptr, or the reason it could not start. A pool that cannot be
  // built refuses startup rather than falling back to the reactor's
  // core, which is the thing it exists to keep free.
  const char* start(unsigned workers, unsigned depth, struct io_uring* home);
  void stop();

  // One declared callback, sent to a worker. `arg` is the argument as
  // CBOR - bytes, because an mrb_value belongs to one VM. False when
  // every slot is taken; the caller decides what a full pool means, and
  // this layer does not invent a refusal for it.
  bool submit(unsigned code_id, std::string_view arg, std::string_view user, double deadline,
              uint64_t answer);
  // What the worker answered. Reading it frees the slot: the answer is
  // handed over once.
  bool take(uint64_t answer, ComputeAnswer* out);
  unsigned workers() const;

  struct Impl;

 private:
  static void worker(Impl* impl, unsigned me);
  Impl* impl_ = nullptr;
};

// Webmachine::Watcher - a description, never a registration. Ruby builds
// one and hands it back; the server arms it. The mask, the abort flag and
// the handle live in its CDATA and NOT in its iv table, which holds
// exactly the two things a GC has to see: the source and the block.
void watcher_init_class(mrb_state* mrb, struct RClass* wm);
bool watcher_p(mrb_state* mrb, mrb_value v);
unsigned watcher_events_mask(mrb_value v);
bool watcher_aborted_p(mrb_value v);
// The seconds a watcher may stay quiet, as `timeout:` gave them.
double watcher_timeout(mrb_value v);
// The deadline passed. The block runs with the `:timeout` event and
// answers what happens next: true says the watcher waits again, false
// says it aborted and the run goes on without it.
bool watcher_deadline_passed(mrb_state* mrb, mrb_value v, mrb_value* said);
int watcher_fd(mrb_value v);
int watcher_slot(mrb_value v);
// #30: when this watcher may be asked why it is quiet, as the whole
// second the sweep reads, or 0 when it owes no deadline. It lives on
// the watcher because a connection can wait on many at once and each
// one allows its own time.
int64_t watcher_deadline_at(mrb_value v);
void watcher_set_deadline_at(mrb_value v, int64_t at);
// #30: the state of the run this watcher belongs to, or nothing. It
// points INTO the coroutine frame that parked - the one thing that
// holds everything about that run - so each watcher finds its own,
// and a connection carrying many runs keeps them apart.
Resource::RunState* watcher_run(mrb_value v);
void watcher_set_run(mrb_value v, Resource::RunState* run);
// #30: which job of the round this watcher answers.
int watcher_job(mrb_value v);
void watcher_set_job(mrb_value v, int job);
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
  void load(mrb_state* mrb, const char* configured);
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

  void open(mrb_state* mrb, const char* zip_path, const MimeDb& mime);

  AssetEntry* find(const char* path, size_t len);

  // What the asset tier weighs one request by: the facts the parse settled
  // - the method among them - and the header values behind them.
  struct AssetRequest {
    const flow::ReqFacts& facts;
    const http::ReqValues& vals;
  };
  uint16_t verdict(const AssetEntry& e, const AssetRequest& r) const;

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
  // A half-open window of the wire body: where it starts and how long
  // it is.
  struct Window {
    size_t off;
    size_t n;
  };
  static unsigned wire_iov(const AssetEntry& e, Window w, iovec* iov);
  static void copy_wire(const AssetEntry& e, Window w, std::string& out);

  // ZIP (APPNOTE): the entry table, for the h2 setup half.
  std::vector<AssetEntry>& entries() { return entries_; }

 private:
  const AssetEntry* find_exact(const char* name, size_t len) const;
  // The Date line for one second, and the second it stands for - what
  // patch_date compares before it rewrites a prebuilt head.
  struct DateStamp {
    const char* line;
    time_t unix_seconds;
  };
  static void patch_date(AssetEntry::Head& h, DateStamp when);

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
  void open(mrb_state* mrb, Assets* assets);
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
  // One error page being asked for: the status it explains, the media slot
  // it renders in, and the words #210 filled in.
  struct Page {
    uint16_t status;
    int slot;
    const Fields& fields;
  };

  // false when there is no page to offer - the caller still owes an
  // answer and falls back to the bodyless status.
  bool render(const Page& p, std::string& out);
  // The bytes this status answers with, whichever way this build has
  // them: the picture where the error assets hold one, the page prepared
  // at boot where the answer names no failure of its own, a render where
  // it does. `held` is the caller's storage and is used for that last
  // case only - the other two are lent where they lie. Null when this
  // build can spell no page at all.
  const char* body_for(const Page& p, std::string& held, size_t* len);

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
    // ls-hpack: lshpack_dec_init leaves the dynamic table's array NULL -
    // lshpack_arr_init is a memset and nothing else - and the first
    // lshpack_arr_push then grows it with
    // memcpy(new_els, arr->els + arr->off, ... * arr->nelem), which is
    // memcpy(new, NULL + 0, 0). NULL + 0 is undefined and memcpy's source
    // is declared non-null, so it trips two UBSan checks at once, on the
    // FIRST dynamic-table insert of every h2 connection - which is to say
    // on the first h2 request the server ever answers.
    //
    // It is not something a caller can pass its way out of, so this is
    // the handover that stops it: the decoder is HANDED a table that
    // already exists, and upstream's first-growth path never runs. 64 is
    // the size upstream would have chosen; lshpack_dec_cleanup frees
    // els, so the allocation belongs to the decoder from here. A failed
    // malloc leaves it exactly as ls-hpack would have left it.
    // The pin is v2.3.5 (cf0f70d, upstream HEAD); this goes when a
    // release grows the array before its first push.
    if (dec.hpd_dyn_table.els == nullptr) {
      constexpr unsigned kFirstTableSlots = 64;
      void* const mem = std::malloc(kFirstTableSlots * sizeof(uintptr_t));
      if (mem != nullptr) {
        dec.hpd_dyn_table.els = static_cast<uintptr_t*>(mem);
        dec.hpd_dyn_table.nalloc = kFirstTableSlots;
      }
    }
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
inline bool ci_eq(std::string_view text, std::string_view lit) {
  const char* const s = text.data();
  const size_t n = text.size();
  const size_t litn = lit.size();
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
// What one negotiation answers: the parameters this endpoint accepted, and
// the Sec-WebSocket-Extensions value to echo back.
struct Negotiated {
  Params& params;
  std::string& echo;
};

inline bool negotiate(std::string_view value, Negotiated out) {
  const char* const v = value.data();
  const size_t len = value.size();
  size_t i = 0;
  while (i < len) {
    while (i < len && (detail::is_ows(v[i]) || v[i] == ',')) i++;
    const size_t name_at = i;
    while (i < len && detail::is_tchar(v[i])) i++;
    const size_t name_len = i - name_at;
    bool ok = detail::ci_eq({v + name_at, name_len}, "permessage-deflate");

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

      if (detail::ci_eq({v + pn_at, pn_len}, "server_no_context_takeover")) {
        if (seen_snct || have_value) { ok = false; continue; }
        seen_snct = true;
        p.server_no_context_takeover = true;
      } else if (detail::ci_eq({v + pn_at, pn_len}, "client_no_context_takeover")) {
        if (seen_cnct || have_value) { ok = false; continue; }
        seen_cnct = true;
        p.client_no_context_takeover = true;
      } else if (detail::ci_eq({v + pn_at, pn_len}, "server_max_window_bits")) {
        uint8_t b = 0;
        if (seen_smwb || !have_value || !detail::window_bits(pv, pv_len, b) ||
            b < kMinRawWindowBits) {
          ok = false;
          continue;
        }
        seen_smwb = true;
        p.server_max_window_bits = b;
      } else if (detail::ci_eq({v + pn_at, pn_len}, "client_max_window_bits")) {
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
      out.params = p;
      out.echo.assign("permessage-deflate");
      if (p.server_no_context_takeover) out.echo.append("; server_no_context_takeover");
      if (p.client_no_context_takeover) out.echo.append("; client_no_context_takeover");
      if (seen_smwb) {
        out.echo.append("; server_max_window_bits=")
            .append(std::to_string(static_cast<unsigned>(p.server_max_window_bits)));
      }
      if (echo_cmwb) {
        out.echo.append("; client_max_window_bits=")
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

void ws_fold(mrb_state* mrb, mrb_value klass, WsResource& out);

bool ws_wants_deflate(const WsResource* r);
WsResource* ws_resource_new();
void ws_resource_free(WsResource* r);

void ws_init(mrb_state* mrb, struct RClass* wm);

// RFC 6455 4.2.2: what admitting one connection answered - the subprotocol
// to echo back, and the status a refusal carries (0 = admitted).
struct WsAdmit {
  std::string& proto;
  uint16_t& status;
};
WsConn* ws_admit(const WsResource* r, Logger* elog, WsAdmit out);

void ws_open(WsConn* c, const wsdeflate::Params& deflate);

bool ws_feed(WsConn* c, std::string_view data, std::string& sink);

void ws_free(WsConn* c);
}

namespace webmachine {
struct SseResource;

struct SseStream;

void sse_fold(mrb_state* mrb, mrb_value klass, SseResource& out);
SseResource* sse_resource_new();
void sse_resource_free(SseResource* r);

void sse_init(mrb_state* mrb, struct RClass* wm);

SseStream* sse_open(const SseResource* r, Logger* log, uint16_t& code);

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
struct Mask {
  const unsigned char* key;  // the frame's four masking octets
  size_t at;                 // how far into the frame the next octet sits
};

inline void unmask_copy(char* dst, std::string_view src, Mask m) {
  for (size_t i = 0; i < src.size(); i++) {
    dst[i] = static_cast<char>(src[i] ^ m.key[(m.at + i) & 3]);
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

// RFC 6455 5.4: the message a frame would join - the opcode it started
// with (0 = nothing in flight), whether it was negotiated deflated, how
// many octets of it have arrived, and the ceiling this connection allows.
struct Message {
  uint8_t op;
  bool deflated;
  uint64_t len;
  uint64_t max;
};

// RFC 6455 5.4 and 7.4.1: may this frame join it? Four scalars are all the
// connection state that decides it - which is why it can be a table too.
inline Head::Err admit(const Head& h, const Message& msg) {
  const uint8_t msg_op = msg.op;
  const bool msg_deflated = msg.deflated;
  const uint64_t msg_len = msg.len;
  const uint64_t max_message = msg.max;
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

// RFC 6455 5.2: what a server frame header says.
struct Frame {
  uint8_t opcode;
  bool fin;
  bool rsv1;
  size_t payload_len;
};
size_t build_header(Frame f, char head[10]);

// RFC 6455 5.5.1: what a Close frame said - the code, and the reason where
// it carried one. 1005 is "the peer named none".
struct Close {
  uint16_t code = 1005;
  std::string_view reason;
};
size_t build_close_payload(Close close, char out[125]);
bool read_close(std::string_view payload, Close& out);
}
}

namespace webmachine {
struct WsResource;
struct WsConn;
namespace wsdeflate { struct Params; }
WsConn* ws_admit(const WsResource* r, Logger* elog, WsAdmit out);
bool ws_wants_deflate(const WsResource* r);
void ws_open(WsConn* c, const wsdeflate::Params& deflate);
bool ws_feed(WsConn* c, std::string_view data, std::string& sink);
void ws_free(WsConn* c);

struct SseResource;
struct SseStream;
SseStream* sse_open(const SseResource* r, Logger* log, uint16_t& code);
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

// http1.cpp's own hint macro, needed here because spell_answer's body
// lives in this header - see the note on spell_answer for why.
#ifndef WM_H1_UNLIKELY
#define WM_H1_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

class Http1 {
 public:
  // ONE of these per connection, so the order is by alignment and not by
  // topic: interleaving the flags with the pointers cost 34 bytes of
  // padding in 176, which is a cache line every five connections spent
  // on nothing. Widest first, the single-byte members last and together.
  struct Plan;

  // #80: a bound run that can STOP. Only a resource that declared a
  // promise or a watch is called through one, so a run that can never
  // stop pays no frame for the ability - the same reasoning #cold-paths
  // applies to code, applied to control flow.
  //
  // WHY a coroutine and not a stage on the connection: at the stop the
  // round's borrowed pointers have to be saved somewhere, and there is
  // no choice about that - `view`, `method`, `path` and every field in
  // ReqValues point into a PROVIDED BUFFER, and on_recv hands that
  // buffer back to the kernel (replenish_/io_uring_buf_ring_advance)
  // before anything could resume. Holding it instead is not an option:
  // the ring has kBufCount of them for the whole process, and a run that
  // parked for 40 ms of argon2 while holding one starves every other
  // connection's recv. So the bytes are copied, and the frame is the one
  // obvious place for the copy rather than a hand-built park struct that
  // has to be re-pointed by hand on the way back.
  //
  // The head and the body are held SEPARATELY even though carry holds
  // them adjacent today: a head is a few hundred bytes and a body may be
  // a megabyte, and the megabyte is the one that will later be spilled to
  // an O_TMPFILE through the ring. A spilled body is not addressable at
  // all until a read completes, so it can never be a span beside the
  // head - it is a descriptor and a length, and fetching it is a second
  // stop this same coroutine takes.
  struct Run {
    struct promise_type;
    using handle = std::coroutine_handle<promise_type>;

    struct promise_type {
      // RFC 9110 15: what the run answered, once it has.
      uint16_t status = 0;
      bool finished = false;
      // Where the answer goes when the run RESUMES, and why the body may
      // not capture them: the plan of the round that started it lived in
      // on_recv's frame and is gone, and the sink may have swapped
      // (out/next) while the run was stopped. The resumer sets these
      // before resume(), and everything after a stop reads them through
      // here rather than through a reference the frame is holding.
      std::string* sink = nullptr;
      struct Plan* plan = nullptr;
      // RFC 9112 9.3: whether the connection lives past this answer. The
      // round decided it before the run started; `spell_next_round` returns it.
      bool persist = true;

      Run get_return_object() { return Run{handle::from_promise(*this)}; }
      // Runs eagerly: a run that never stops must reach its answer inside
      // the call that started it, exactly as resource_run does today.
      std::suspend_never initial_suspend() noexcept { return {}; }
      // Suspends at the end so the caller can read `status` off the frame
      // and destroy it deliberately - a self-destroying coroutine would
      // take the answer with it.
      std::suspend_always final_suspend() noexcept { return {}; }
      void return_value(uint16_t s) {
        status = s;
        finished = true;
      }
      // #mruby-raises: a raise IS a C++ throw here, and the run frames
      // above already catch it. Rethrowing leaves this frame suspended at
      // its final point, which is where the caller destroys it.
      void unhandled_exception() { throw; }
    };

    Run() = default;
    explicit Run(handle h) : co(h) {}
    Run(const Run&) = delete;
    Run& operator=(const Run&) = delete;
    Run(Run&& o) noexcept : co(o.co) { o.co = {}; }
    Run& operator=(Run&& o) noexcept {
      if (this != &o) {
        destroy();
        co = o.co;
        o.co = {};
      }
      return *this;
    }
    ~Run() { destroy(); }

    // Did it reach an answer, or is it parked on something?
    bool done() const { return !co || co.promise().finished; }
    uint16_t status() const { return co ? co.promise().status : 0; }
    void destroy() {
      if (co) co.destroy();
      co = {};
    }
    // Handed to whatever will resume it - the reactor keeps this and
    // nothing else, because the handle IS the parked run's name. There is
    // no slot table and no tag field to translate.
    handle release() {
      const handle h = co;
      co = {};
      return h;
    }

    handle co{};
  };

  // #80: the stop itself. It always suspends, and what it hands back on
  // the way in is the run's OWN promise - because the sink and the plan
  // it must write into belong to the round that RESUMED it, not to the
  // round that started it. The resumer sets them just before resume(),
  // so reading them through the promise is the only way to read the
  // right ones. A reference captured before the stop would name a sink
  // that is gone.
  struct Park {
    Run::promise_type* p = nullptr;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(Run::handle h) noexcept {
      p = &h.promise();
      return true;
    }
    Run::promise_type& await_resume() const noexcept { return *p; }
  };

  // The same door, held open. A coroutine cannot name its own promise,
  // and the run has to write into it before it ever stops: `persist` is
  // the request's answer and the caller reads it off the frame. So this
  // asks for the promise and refuses to suspend - await_suspend saying
  // false means "carry on", which is the standard way to read your own
  // frame without leaving it.
  struct Self {
    Run::promise_type* p = nullptr;
    bool await_ready() const noexcept { return false; }
    bool await_suspend(Run::handle h) noexcept {
      p = &h.promise();
      return false;
    }
    Run::promise_type& await_resume() const noexcept { return *p; }
  };


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
    // #80: the run this connection stopped, if it stopped one. The handle
    // IS its name - there is no slot table and no id to look it up by,
    // which is what the scaffolding this replaces was reaching for.
    Run parked;

    // The width of one value round: an ETag, a Last-Modified, an
    // Expires and a body. Nothing in the flow asks for a fifth.
    static constexpr int kJobSlots = kValueJobs;
    // Is a run stopped on this connection? Nothing else may speak for it
    // while one is - not the carry behind it, and not a pipelined request
    // (RFC 9112 9.3.2: responses go out in the order the requests came).
    bool run_parked() const { return static_cast<bool>(parked.co) && !parked.done(); }

    // #30: everything ONE stopped run waits on.
    //
    // It is a struct of its own because a connection can hold more than
    // one. h1 holds a single stopped run - RFC 9112 9.3.2 puts the
    // answers out in the order the requests came - but an h2 connection
    // multiplexes streams, and every stream that stops is a run with its
    // own jobs, its own watchers and its own answers.
    struct Round {
      // #80: what the worker said, in THIS VM's values. The reactor puts
      // it here on the way in and the resumed walk reads it once. It is
      // rooted while it waits - nothing on the VM's stack names it.
      //
      // #30: one answer per job. A value round starts several jobs at
      // once - the flow says generate_etag, last_modified and the body
      // render do not decide anything for each other - so the channel is
      // as wide as the round. Slot 0 is the single job's, and a
      // watcher's.
      mrb_value answer_value[kJobSlots] = {};
      // Every job of the round answered; the resume is where the run
      // picks that up, because that is the one point at which a fresh
      // sink and a fresh plan exist to write into.
      bool answer_ready = false;
      // #80: the work a stopped run left, ALREADY across. The frame does
      // the crossing itself, at the stop, because that is the last
      // moment the reactor's VM and the run's own state are both to
      // hand - the frame takes that state with it one line later.
      struct Job {
        unsigned code = 0;
        std::string bytes;
        double deadline = 0.0;
        // #30: response.userdata as CBOR, or empty when the run put
        // nothing there. Every job of a round gets the same bytes.
        std::string user_bytes;
        // The reactor has not armed this one yet.
        bool waiting = false;
      };
      Job job[kJobSlots];
      // Which value each job of the round answers - kJobNode for a
      // node's own callback. A watcher fills its place here too, and it
      // has no Job: nothing crosses to a worker for it.
      uint8_t job_what[kJobSlots] = {};
      // #30: response.userdata as the worker left it, per job, when the
      // worker changed it. Rooted like an answer, read at the resume.
      mrb_value user_value[kJobSlots] = {};
      bool user_have[kJobSlots] = {};
      // How many jobs this stop handed over, and how many answered. The
      // run goes on when the two are equal.
      uint8_t jobs_owed = 0;
      uint8_t jobs_answered = 0;
      // Whose VM the answer is decoded back into. It outlives the
      // crossing, because the answer comes long after.
      const Resource* job_res = nullptr;
      // #30: the watcher slot each job of this round waits on, or -1.
      int w_slot[kValueJobs] = {-1, -1, -1, -1};
      // The pool had no slot: LOAD, and load passes. 429 with a
      // Retry-After of a few seconds (.DESIGN.md #promise-bound).
      bool compute_task_full = false;
      // The worker ended the task at its max_runtime. NOT load: a second
      // attempt costs the same, so 500 and no Retry-After.
      bool compute_task_over_deadline = false;
      // The worker raised. The registry holds what dies - a database, a
      // connection - so 503 with a Retry-After of a minute.
      bool compute_task_raised = false;
    };
    // #30: where each stopped run of this connection keeps what it
    // waits on. The Round itself lives in the COROUTINE FRAME of that
    // run - the frame holds everything about it and stays alive while
    // it waits - and this table is only what the reactor needs: an
    // answer arrives as a completion, and a completion carries a
    // number, not an address.
    //
    // Four bits of the tag name the park slot and four name the job, so
    // one byte carries both and the layout is unchanged.
    // h1 stops at most one run per connection - RFC 9112 9.3.2 puts the
    // answers out in the order the requests came - so it remembers the
    // one slot it took. An h2 stream remembers its own.
    int h1_park = -1;
    static constexpr int kParkSlots = 16;
    Round* park[kParkSlots] = {};
    // Which parked runs have a job the reactor has not armed yet. Asked
    // on every round, so it is a list and not a search over the table.
    std::vector<int> park_pending;
    void park_wants_arming(int slot) {
      for (const int at : park_pending) {
        if (at == slot) return;
      }
      park_pending.push_back(slot);
    }

    // A slot for a run that is stopping, or -1 when this connection
    // holds as many as a tag can name.
    int park_take(Round* r) {
      for (int i = 0; i < kParkSlots; i++) {
        if (park[i] != nullptr) continue;
        park[i] = r;
        return i;
      }
      return -1;
    }
    void park_drop(int slot) {
      if (slot < 0 || slot >= kParkSlots) return;
      park[slot] = nullptr;
      for (size_t i = 0; i < park_pending.size(); i++) {
        if (park_pending[i] != slot) continue;
        park_pending.erase(park_pending.begin() + static_cast<long>(i));
        break;
      }
    }
    Round* park_at(int slot) const {
      if (slot < 0 || slot >= kParkSlots) return nullptr;
      return park[slot];
    }
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
    // spelled and `spell_next_round` may put it on the wire. Nothing else about the
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
    // A slot is built in place and moved once, when conns_ is sized.
    // Declared because the destructor below suppresses the implicit move,
    // and Run is move-only - without these the vector falls back to a
    // copy, which a coroutine handle must never have.
    // #80: Run is move-only (a coroutine handle must never be copied),
    // which deletes the implicit copy this struct used to have. Nothing
    // is declared in its place ON PURPOSE: a slot is built where it
    // lives and never moves, so the vector became a unique_ptr array -
    // see conns_. A defaulted move here would copy ws/sse/h2/file and
    // the GC registration and leave the source owning them too, and a
    // hand-written one is a member list that can be short by one.
    Conn() = default;
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;

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
  void open_error_assets(mrb_state* mrb, Assets* error_assets);

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

  // Where an answer goes: the bytes the round appends to, and the plan
  // that will carry them (null where this caller is not planning a send).
  struct Sink {
    std::string& bytes;
    Plan* plan;
  };
  bool feed(Conn& st, std::string_view data, Sink out);

  // The sink has drained, and this connection may still owe bytes: a
  // stopped run, a file transfer, an event stream, an h2 frame, an
  // asset. This spells the next round of them, and when nothing is owed
  // it takes the next request out of the carry. It answers whether the
  // connection lives past that round.
  bool spell_next_round(Conn& st, std::string& sink, Plan& plan);

  // #80: the reactor saying a worker or a watcher answered. Only a flag -
  // the run is resumed in `spell_next_round`, where a sink and a plan exist.
  // The worker answered. The bytes come back into the reactor's VM
  // here, which is the only thread that may build a value in it. A
  // worker that raised, or an answer CBOR cannot carry, is nil - the
  // run reads it like any other answer and decides for itself.
  static void compute_task_answered(Conn& st, int park, int job, const ComputeAnswer& answered);
  // #30: one job of a round answered, whatever answered it.
  static void round_answered(Conn::Round& r, int job, mrb_value v);
  // The job a stopped run left, or nullptr. Taken, not read: the reactor
  // arms it once and the connection stops naming it - exactly file_take.
  // Every worker slot is taken. The run is told rather than the layer
  // inventing a refusal - it answers this the way it answers anything.
  static void compute_task_refused(Conn& st, int park) {
    Conn::Round* const r = st.park_at(park);
    if (r == nullptr) return;
    r->answer_ready = true;
    r->compute_task_full = true;
  }
  // The three refusals a stopped run can meet, told apart here so no
  // call site has to (.DESIGN.md #promise-bound). Status 0 means the
  // worker answered and the run reads the answer.
  //
  // Retry-After holds a whole header line, ready to append: these are
  // the only three the refusals send, and they are constants so a
  // refusal costs no formatting and no allocation.
  struct ComputeRefusal {
    uint16_t status = 0;
    std::string_view retry_after;
  };
  static ComputeRefusal compute_task_refusal(Conn::Round& round) {
    // A full pool is load, and load passes. The seconds move over 3..5
    // so a burst that was refused together does not come back together.
    if (round.compute_task_full) {
      static const char* const kWait[3] = {"Retry-After: 3\r\n", "Retry-After: 4\r\n",
                                           "Retry-After: 5\r\n"};
      static unsigned turn = 0;
      return {429, kWait[turn++ % 3]};
    }
    // The author's number was wrong. Coming back does not make the work
    // shorter, so nothing tells the client to.
    if (round.compute_task_over_deadline) return {500, {}};
    // A handle the worker needs is gone. A database that is restarted
    // comes back, and a minute is the size of that, not the seconds a
    // burst of load lives on.
    if (round.compute_task_raised) return {503, "Retry-After: 60\r\n"};
    return {};
  }
  // #80: the crossing, done by the frame at the stop. The block becomes
  // an id and the arguments become CBOR. After this nothing of the VM is
  // named, which is what lets a worker touch the result at all.
  static bool compute_task_hand_over(Conn& st, Conn::Round& round, int park, const Resource& res);
  // #30: the watcher a stopped run left, handed to the connection. The
  // connection files it under a slot and roots it; the reactor arms what
  // `w_pending` names. False when the connection can hold no more, and
  // the run is told the way a full pool tells it.
  static bool watch_hand_over(Conn& st, Conn::Round& round, int park, const Resource& res);
  // What one event did to the wait.
  enum class WatchStep : uint8_t {
    kWait,    // the block wants the same thing again
    kRearm,   // the block asked for other events
    kDone,    // the block called abort; `answer_value` is its last word
  };
  // #30: one readiness, delivered to the block. The block decides what
  // happens next, and it says so through the watcher: `abort` ends the
  // wait, `events=` changes what to wait for, anything else waits again.
  // The RETURN VALUE never means "keep waiting" - a block may answer nil
  // and mean it.
  static WatchStep watcher_event(Conn& st, int slot, unsigned revents);
  // The watcher was quiet for as long as it allowed. The block hears
  // `:timeout` and answers whether the wait goes on.
  static WatchStep watcher_deadline(Conn& st, int slot);
  // What a watcher waits for right now, as poll bits, and how long it
  // may stay quiet. The reactor asks both when it arms one.
  static unsigned watcher_mask(Conn& st, int slot);
  static int watcher_descriptor(Conn& st, int slot);
  static void watcher_is_armed(Conn& st, int slot, struct io_uring* ring);
  static void watchers_drop_slot(Conn& st, int slot);
  // A watcher this connection has not armed yet. Taken, not read: the
  // reactor arms it once and the connection stops naming it - exactly
  // file_take and compute_task_take.
  static bool watch_take(Conn& st, int* slot) {
    if (st.w_pending.empty()) return false;
    *slot = st.w_pending.back();
    st.w_pending.pop_back();
    return true;
  }
  // Which watcher this connection waits on, or -1.
  // #30: the watcher slot each job of the round waits on, or -1. A
  // round can wait on several at once.
  // The other way round: which job a watcher slot answers, or -1 when
  // this connection is not waiting on it.
  // #30: where the run that owns these watchers is waiting. Told after
  // the park, because only then does the frame hold its own state.
  static void watch_run_is(Conn& st, Conn::Round& round, Resource::RunState* run);
  // #30: every watcher of this connection that stayed quiet for as long
  // as IT allowed. The sweep asks once per connection, not once per
  // watcher, and this walks the ones that are armed.
  static size_t watchers_over_deadline(Conn& st, int64_t now, int* slots, size_t max);
  // The earliest deadline any armed watcher of this connection owes, or
  // 0 when none does. The Ring keeps that one number.
  static int64_t watchers_soonest_deadline(Conn& st);
  static void watcher_armed_at(Conn& st, int slot, int64_t at);
  static double watcher_quiet_seconds(Conn& st, int slot);
  // The work a stopped run left, or false. Taken, not read: the reactor
  // arms it once and the connection stops naming it - exactly file_take.
  // #30: response.userdata for this job, as the crossing left it.
  static std::string_view compute_task_user(const Conn& st, int park, int job) {
    const Conn::Round* const r = st.park_at(park);
    if (r == nullptr || job < 0 || job >= Conn::kJobSlots) return {};
    return r->job[job].user_bytes;
  }
  static bool compute_task_take(Conn& st, int park, int job, unsigned* code, std::string& bytes,
                                double* deadline) {
    Conn::Round* const r = st.park_at(park);
    if (r == nullptr || job < 0 || job >= Conn::kJobSlots) return false;
    Conn::Round::Job& j = r->job[job];
    if (!j.waiting) return false;
    *code = j.code;
    *deadline = j.deadline;
    bytes.swap(j.bytes);
    j.bytes.clear();
    j.waiting = false;
    return true;
  }
  // Is this connection waiting on one? The Ring asks before it lets
  // anything else speak for the connection.
  static bool run_answer_pending(const Conn& st) {
    if (!st.run_parked()) return false;
    const Conn::Round* const r = st.park_at(st.h1_park);
    return r == nullptr || !r->answer_ready;
  }

  // response.file, the reactor's half. A bound run may name a file instead
  // of spelling a body; opening it is disk work, so it never happens inside
  // the run. These five are the whole contract with the Ring - it drives
  // openat2/statx/read through the ring and hands each result back here,
  // and the answer reaches the wire through `spell_next_round` like every other
  // continuation. Any refusal - a miss, a directory, a resolve flag
  // catching an escape - lands as the SAME 404 file_reject spells.
  const char* file_take(Conn& st);
  // The question file_take answers, asked without a call. The reactor
  // asks it on EVERY recv and every round, and the answer is almost
  // always no: file_take lives in another translation unit, so the no
  // cost a call and a return. Measured at 0.38% of a whole h1 run.
  static bool file_waiting(const Conn& st) {
    return st.file != nullptr && st.file->stage == FileStage::kNamed;
  }
  // The same, for the work a stopped run left. arm_compute_task built a
  // std::string before it asked. Measured at 0.45%.
  static bool compute_task_waiting(const Conn& st) { return !st.park_pending.empty(); }
  // The next parked run with a job to arm, or false. Taken, not read -
  // the same shape as file_take and watch_take.
  static bool park_take_pending(Conn& st, int* park) {
    if (st.park_pending.empty()) return false;
    *park = st.park_pending.back();
    st.park_pending.pop_back();
    return true;
  }
  void file_reject(Conn& st);
  void file_error(Conn& st, const char* why);
  bool file_stat(Conn& st, const struct statx& stx, size_t* want);
  char* file_buffer(Conn& st, size_t n);
  void file_ready_now(Conn& st, size_t n);
  void file_mapped(Conn& st, const char* p, size_t n);
  // Is a round waiting for `spell_next_round` to run? kDone counts: it puts nothing on
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
  // What one run left behind, which is all the shape depends on: the status
  // it reached, the body it spelled or lent, whether the head branch above
  // already answered, and what the route allows.
  struct AnswerFacts {
    uint16_t status;
    size_t body_len;
    size_t lent_len;
    bool answered_already;
    bool have_body;
    bool has_lent;
    bool gzip_ok;
    bool bound;
  };
  static AnswerStep answer_step(const AnswerFacts& f) {
    AnswerStep s;
    s.body_len = f.has_lent ? f.lent_len : f.body_len;
    s.answered = f.answered_already;
    if (f.have_body && f.status == 200) {
      s.shape = f.has_lent ? AnswerStep::Shape::kLent
                           : (f.gzip_ok ? AnswerStep::Shape::kGzip : AnswerStep::Shape::kPlain);
      s.answered = true;
    } else if (f.answered_already) {
      s.shape = AnswerStep::Shape::kAlready;
    } else if (f.status == 500 && f.bound) {
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
  // What the connection allows this round: what is left of its own flow
  // window, and the largest copy this round is willing to make.
  struct RoundRoom {
    int64_t conn_window;
    size_t chunk;
  };
  static H2SendStep h2_send_step(const H2Stream& s, RoundRoom room) {
    const int64_t conn_window = room.conn_window;
    const size_t chunk = room.chunk;
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
  struct AssetStep {
    // Which of the four heads this request gets; the enum is HeadKind, not
    // Head, because AssetEntry::Head is a head - this only picks one.
    enum class HeadKind : uint8_t { kRefusal, kNormal, kRange, kUnsatisfiable };
    HeadKind head = HeadKind::kNormal;
    uint16_t status_code = 200;
    size_t first_byte_pos = 0;
    size_t content_length = 0;
    bool sends_content = false;
  };
  // RFC 9110 14.1/14.2: a range is honoured only on a GET that would have
  // been a 200, and only when If-Range still matches the representation.
  // What the range decision weighs besides the entry: the verdict c4 has
  // already reached, and what the request asked for.
  struct RangeAsk {
    uint16_t verdict;
    bool head_only;
    flow::Method method;
    const http::ReqValues& vals;
  };
  static AssetStep asset_step(const AssetEntry& e, const RangeAsk& ask) {
    const uint16_t verdict = ask.verdict;
    const bool head_only = ask.head_only;
    const http::ReqValues& vals = ask.vals;
    AssetStep s;
    s.status_code = verdict;
    if (verdict == 412 || verdict == 501) {
      s.head = AssetStep::HeadKind::kRefusal;
      return s;
    }
    const size_t complete_length = Assets::wire_len(e);
    if (verdict == 200 && !head_only && ask.method == flow::Method::kGet &&
        vals.range != nullptr &&
        (vals.if_range == nullptr ||
         http::if_range_matches({vals.if_range, vals.if_range_len}, {e.etag, sizeof(e.etag)}))) {
      http::ByteRange r = {0, 0};
      switch (http::parse_range({{vals.range, vals.range_len}, complete_length}, r)) {
        case http::RangeParse::kOne:
          s.head = AssetStep::HeadKind::kRange;
          s.status_code = 206;
          s.first_byte_pos = r.first;
          s.content_length = r.last - r.first + 1;
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
    return s;
  }

  // The next round of a transfer, computed and not performed.
  //
  // Defined HERE, not in a .cpp: `spell_next_round` lives in another translation unit
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
  // RFC 9112 9.3: one status prebuilt - the code, the fields that always go
  // with it, the body it carries where it carries one, the Date bytes laid
  // down (a placeholder at boot; the second's own from then on), and the
  // Connection field of the spelling being built.
  struct Prebuilt {
    uint16_t status;
    const char* extra;
    const char* body;
    const char* date;
    const char* conn = "";
  };
  static void build_variants(Variants& v, Prebuilt p);
  static void build_one_variant(Resp& r, Prebuilt p);
  static void copy_without_tail(const Resp& src, Resp& dst, size_t cut);
  // RFC 9112: a head that stops before Content-Length, for a body the run
  // has yet to produce - the status line, the route's own fields, whatever
  // Vary / Content-Encoding applies, and the Connection field of the
  // spelling being built.
  struct OpenPrefix {
    const char* status_line;
    const std::string& extra;
    const char* enc;
    const char* conn = "";
  };
  static void build_open_prefixes(Variants& v, OpenPrefix p);
  static void build_open_prefix(Resp& r, OpenPrefix p);
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
  // What one prebuilt status says beyond its status line: the fields that
  // always go with it, and the body it carries where it carries one.
  struct StatusText {
    const char* extra;
    const char* body;
  };
  void build_status(uint16_t status, StatusText t);
  void stock_status(bool have[600], uint16_t s);
  void build_bundle(Bundle& b, const Resource* res);
  static void patch_date(Variants& v, const char* core);
  // RFC 9112: one prebuilt head and the body behind it - a HEAD request
  // takes the same head and none of the bytes.
  struct Assembled {
    const Resp& prefix;
    std::string_view body;
    bool head_only;
  };
  static void assemble(std::string& sink, const Assembled& a);
  bool feed_parse(Conn& st, std::string_view data, Sink out);
  static void claim_sink(Conn& st, const std::string& sink, Plan& plan);
  // The bytes one answer LENDS rather than copies, and the plan they are
  // lent into.
  struct Lending {
    std::string_view body;
    Plan& plan;
  };
  static void lend_body(Conn& st, std::string& sink, Lending lend);
  // RFC 9110 12.5.3/12.5.5: what a dynamic 200 chooses between - the two
  // prebuilt prefixes, whether gzip is on the table at all (the peer
  // accepts it AND this connection is packetized), and whether the request
  // wants the body behind the head.
  struct DynamicBody {
    const Resp& prefix_id;
    const Resp& prefix_gz;
    // The bytes the run spelled. Handed in, never read off a member: a
    // parked run writes into its own string, and the writer's own is
    // already carrying the next request by the time this runs.
    const std::string& body;
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
  // #80: everything a stopped run BORROWED, rebased onto bytes it owns.
  // Named Held and not Parked because Http1 already has a Parked, and
  // that one is an h2 stream's view - a different thing entirely.
  //
  // What borrows, and it is more than ReqValues: ReqView's
  // request_target and method_token, the framer's phr_header array with
  // a name and a value each, and RouteSpans' captures. All of it points
  // into ONE contiguous head - the provided buffer, or carry - so one
  // delta moves the lot, and the only way to get that wrong is to miss a
  // member. Hence kReqValueSpans and its size assert.
  //
  // The BODY is not held here. Today it is the bytes right behind the
  // head and could ride along; tomorrow it is an O_TMPFILE that a read
  // has to fetch, and then it is not a span at all. Holding it apart
  // from the start is what keeps that from being a second rewrite.
  struct Held {
    // The bytes. Everything below points INTO this string, so it must
    // not move once hold() has run - no append, no reserve, no swap.
    std::string head;
    http::ReqValues vals{};
    RouteSpans spans{};
    ReqView rv{};
    std::unique_ptr<struct phr_header[]> fields;
    size_t nfields = 0;

    Held();
    ~Held();
    Held(Held&&) noexcept;
    Held& operator=(Held&&) noexcept;
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;

    // Copy the head and re-point `from` at the copy. After this the
    // provided buffer may go back to the kernel, which is the whole
    // point - see Run.
    void hold(const char* head_at, size_t head_len, const ReqView& from);
  };

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

  // #80: what the BOUND answer needs beyond the Round. The bound branch
  // used to sit inline in feed_parse, and it has to leave: a run that
  // parks returns out of it and comes back later, which an inline block
  // in a loop body cannot do. Same rule as Spelling below - these
  // travelled together as a dozen arguments, so they are a type.
  struct BoundAsk {
    const void* fields;
    size_t nfields;
    const RouteSpans& spans;
    const RouteTable* table;
    int route;
    Plan* plan;
    std::string& sink;
    // Where the run writes its body and its field lines. They used to be
    // two Http1 members, reused request after request. A run that PARKS
    // may not share them: the next request on this connection's ring
    // would write over what the parked one still owes, so a parked run
    // brings its own and the straight path keeps handing in the pair it
    // always reused.
    std::string& body;
    std::string& rhdrs;
  };
  // What the bound branch produced. `answered` means it spelled its own
  // head into the sink and the answer switch has nothing left to do.
  struct BoundOut {
    uint16_t status = 0;
    bool have_body = false;
    bool answered = false;
    // Read once here and used twice: the zero-copy gate inside, and
    // assemble_dynamic in the answer switch outside. Accept-Encoding does
    // not change between the two, so it is not read twice.
    bool accept_gzip = false;
    const char* lent = nullptr;
    size_t lent_len = 0;
  };
  // What the walk is handed, built once and read by both entries. The
  // ReqView is a member and not a return value because everything in it
  // POINTS at bytes somebody else owns, and the owner has to outlive it.
  struct BoundPrep {
    ReqView rv;
    size_t zc_min = 0;
    bool accept_gzip = false;
  };
  void bound_prepare(Round& r, const BoundAsk& ask, BoundPrep& prep);

  // #80: everything a stopped run has to keep about the REQUEST, by
  // value. The Round it is built from holds references into feed_parse's
  // frame, and that frame is gone the moment the run stops - so the
  // coroutine takes copies and re-seats them at `head` once hold() has
  // run.
  struct BoundStart {
    const Bundle* b;
    const char* head_at;  // the request head's first byte, for hold()
    const char* view;
    size_t viewlen;
    size_t off;
    size_t head_len;
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    size_t content_length;
    const void* fields;
    size_t nfields;
    RouteSpans spans;
    const RouteTable* table;
    flow::ReqFacts facts;
    http::ReqValues vals;
    int route;
    int minor;
    uint8_t lflags;
    bool in_place;
    bool persist;
    bool head_only;
  };
  // The whole bound answer for a resource that declared a compute task, in a
  // frame that can stop. A resource that declared none never reaches
  // this and pays no frame.
  // #30: what a parkable run starts from. One coroutine serves both
  // protocols, because there must be ONE place where a run stops: the
  // frame that suspends holds everything about that run, and a second
  // copy of this machinery would be a second answer to the same
  // question. The tails differ - h1 spells a head and a body, h2 frames
  // HEADERS and DATA - and the stop between them does not.
  struct RunStart {
    enum class Proto : uint8_t { kH1, kH2 };
    Proto proto = Proto::kH1;
    // proto == kH1. The bytes of the request, and everything the parse
    // read out of them.
    BoundStart h1{};
  };
  Run run_parkable(Conn& st, RunStart s, std::string* sink, Plan* plan);
  // What one such round leaves for the parse to do next.
  enum class ComputeRound : uint8_t {
    kNext,    // answered here; read the next request out of this buffer
    kParked,  // stopped; what is left waits in the carry
    kClosed,  // the answer was the connection's last
  };
  // The whole compute round, OUT of feed_parse. It is cold - a resource
  // that never said `compute` does not reach it - and feed_parse is the
  // hottest function in the server, 20764 bytes against a 32 KiB L1i
  // (.DESIGN.md #cold-paths, which measured ~14 KB before this branch
  // existed). Inlined here it was paid for by every request that never
  // ran a compute task.
  __attribute__((noinline)) ComputeRound start_compute_round(Conn& st, const BoundStart& s,
                                                             std::string* sink, Plan* plan,
                                                             size_t& off);

  // kOwed = nothing is answered yet: the body is still coming, or a file
  // is being fetched through the ring.
  Took answer_bound(Round& r, const BoundAsk& ask, BoundOut& out);
  // The half after the walk. Reached from answer_bound and, once a run
  // can park, from the coroutine a promising resource runs through.
  Took bound_finish(Round& r, const BoundAsk& ask, BoundOut& out);

  // #80: what the answer switch needs beyond the Round - the sink it
  // writes to, the plan a lend rides out on, and what the run left
  // behind. A struct because these travelled together as nine
  // arguments, and #std-first says that is a type.
  struct Spelling {
    std::string& sink;
    Plan* plan;
    uint16_t status;
    const char* lent;
    size_t lent_len;
    bool answered;
    bool have_body;
    bool accept_gzip;
    const std::array<uint16_t, 600>* idx;
    // Same reason as DynamicBody::body: the run that spelled these bytes
    // may be one that stopped, and then they are not the writer's.
    const std::string& body;
  };
  // #80: the answer, spelled. Split out of feed_parse so the bound tier can
  // reach it from inside a coroutine while the konst tier keeps calling it
  // straight - a run that can never stop must not pay for a frame.
  // Returns the step it took, because the access line counts what it wrote.
  AnswerStep spell_answer(Round& r, Spelling sp) {
    Conn& st = r.st;
    const Bundle* const b = r.b;
    const int minor = r.minor;
    const bool persist = r.persist;
    const bool head_only = r.head_only;
    const http::ReqValues& vals = r.vals;
    const char* const method = r.method;
    const size_t method_len = r.method_len;
    const char* const path = r.path;
    const size_t path_len = r.path_len;
    std::string& sink = sp.sink;
    Plan* const plan = sp.plan;
    const uint16_t status = sp.status;
    const char* const lent = sp.lent;
    const size_t lent_len = sp.lent_len;
    const bool answered = sp.answered;
    const bool have_body = sp.have_body;
    const bool accept_gzip = sp.accept_gzip;
    const std::array<uint16_t, 600>* const idx = sp.idx;
    AnswerStep astep = answer_step({status, sp.body.size(), lent_len, answered, have_body,
                                    lent != nullptr, b != nullptr && b->gzip_ok,
                                    b != nullptr && b->bound});
    mrb_value exc_value = mrb_nil_value();
    // #210: what led here, gathered once - the record and the page carry
    // the same hash because they are taken over the same facts.
    ErrFacts ef;
    std::string ef_backtrace;
    std::string ef_steering;
    char ef_hash[kFingerprintLen] = {};
    if (WM_H1_UNLIKELY(astep.shape == AnswerStep::Shape::kException)) {
      ef.peer = st.peer;
      ef.peer_len = st.peer_len;
      ef.request_target = path;
      ef.request_target_len = path_len;
      ef.method = method;
      ef.method_len = method_len;
      spell_steering(&vals, ef_steering);
      ef.steering = ef_steering.data();
      ef.steering_len = ef_steering.size();
      // The request as the resource saw it: lent for this frame, which is
      // the frame still being answered.
      ef.body = b->res->run.req != nullptr ? b->res->run.req->content : nullptr;
      ef.body_len = b->res->run.req != nullptr ? b->res->run.req->content_len : 0;
      ef.body_full = ef.body_len;
      ef.status_code = 500;
      exception_facts(b->res->mrb, {ef, ef_backtrace});
      spell_fingerprint(ef_hash, fingerprint_of(ef));
      if (elog_.enabled) log_error(elog_, ef);
      // #210: handle_exception lives on the error resource and nowhere
      // else, so the exception object itself is what crosses over - not
      // a message some resource already made of it.
      if (resource_exception_take(*b->res, &exc_value)) astep.answered = true;
      else astep.shape = AnswerStep::Shape::kStatus;
    }
    switch (astep.shape) {
      case AnswerStep::Shape::kAlready:
        break;
      case AnswerStep::Shape::kLent: {
        const Variants& pv = b->gzip_ok ? b->ok_prefix_vary : b->ok_prefix;
        const Resp& pfx = minor >= 1 ? (persist ? pv.plain : pv.close)
                                     : (persist ? pv.keep : pv.close);
        sink.append(pfx.bytes);
        char cl[40];
        sink.append(cl, http::spell_content_length(cl, lent_len));
        lend_body(st, sink, {{lent, lent_len}, *plan});
        break;
      }
      case AnswerStep::Shape::kGzip: {
        const Resp& prefix_id =
            minor >= 1 ? (persist ? b->ok_prefix_vary.plain : b->ok_prefix_vary.close)
                       : (persist ? b->ok_prefix_vary.keep : b->ok_prefix_vary.close);
        const Resp& prefix_gz =
            minor >= 1 ? (persist ? b->ok_prefix_gzip.plain : b->ok_prefix_gzip.close)
                       : (persist ? b->ok_prefix_gzip.keep : b->ok_prefix_gzip.close);
        assemble_dynamic({prefix_id, prefix_gz, sp.body, accept_gzip && st.packetized, head_only}, sink);
        break;
      }
      case AnswerStep::Shape::kPlain: {
        const Resp& prefix = minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                        : (persist ? b->ok_prefix.keep : b->ok_prefix.close);
        assemble(sink, {prefix, sp.body, head_only});
        break;
      }
      case AnswerStep::Shape::kException: {
        std::string message;
        err_pages_.exception_text(exc_value, message);
        const Variants& pv = store_prefix_[(*idx)[500]];
        const Variants& bv = store_[(*idx)[500]];
        ErrorPages::Fields f;
        f.message = message.data();
        f.message_len = message.size();
        f.fingerprint = ef_hash;
        // A ship build says what was thrown and where the log has the rest; a
        // debug build is already telling you about itself, so the trace goes
        // on the page too.
        if (kDebugBuild) {
          f.backtrace = ef.backtrace;
          f.backtrace_len = ef.backtrace_len;
        }
        const Resp& prefix = minor >= 1 ? (persist ? pv.plain : pv.close)
                                        : (persist ? pv.keep : pv.close);
        const Resp& bodyless = minor >= 1 ? (persist ? bv.plain : bv.close)
                                          : (persist ? bv.keep : bv.close);
        spell_error({prefix, bodyless, 500,
                     err_pages_.media_for(500, vals.accept, vals.accept_len), f, head_only},
                    sink);
        break;
      }
      case AnswerStep::Shape::kStatus: {
        const Variants& sv =
            (head_only && status == 200) ? b->ok_head : store_[(*idx)[status]];
        const Resp& bodyless = minor >= 1 ? (persist ? sv.plain : sv.close)
                                          : (persist ? sv.keep : sv.close);
        // RFC 9110 15: only a 4xx or 5xx has something to explain. A 204,
        // a 304 or a redirect is an answer, and answers carry no page.
        if (status >= 400) {
          const Variants& pv = store_prefix_[(*idx)[status]];
          const ErrorPages::Fields f;
          const Resp& prefix = minor >= 1 ? (persist ? pv.plain : pv.close)
                                          : (persist ? pv.keep : pv.close);
          spell_error({prefix, bodyless, status,
                       err_pages_.media_for(status, vals.accept, vals.accept_len), f, head_only},
                      sink);
        } else if (status == 200 && !head_only && plan != nullptr &&
                   b->konst.body.size() >= kLendFloor) {
          // The konst body is a std::string built at SETUP and immortal for
          // the life of the process - no mrb_value, nothing for the GC to
          // move or collect, so it is LENT as a pointer rather than copied
          // into this connection's sink. Copying it cost every stalled
          // reader a private duplicate of the same answer.
          //
          // From kLendFloor up. Below it the whole prebuilt 200 goes into
          // the sink - head, Content-Length and body in one piece - and
          // the round leaves as ONE send.
          const Resp& pfx = minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                       : (persist ? b->ok_prefix.keep : b->ok_prefix.close);
          sink.append(pfx.bytes);
          char cl[40];
          sink.append(cl, http::spell_content_length(cl, b->konst.body.size()));
          lend_body(st, sink, {{b->konst.body.data(), b->konst.body.size()}, *plan});
        } else {
          sink.append(bodyless.bytes);
        }
        break;
      }
    }
    return astep;
  }

  // RFC 9110 6.3: response.file named a file, so no body is spelled here
  // - the framing goes onto the connection and the reactor drives
  // openat2/statx/read. Answers whether it took the round.
  bool answer_from_file(Round& r, uint16_t status, const std::string& rhdrs);

  // RFC 9110 6.3 / RFC 9111: a mounted archive answers this target, head
  // and body, without the flow or the VM. /error_assets/ resolves against
  // the error archive, everything else against --assets.
  Took answer_from_assets(Round& r, std::string& sink, Plan* plan);

  bool fail(Conn& st, uint16_t code, std::string& out, uint8_t log = 0);
  // response.file's answer, head only - the bytes ride after it as a lent
  // segment. `prebuilt` takes the status straight out of the shared store.
  // The head a served file wears: the status it carries, how many octets
  // it declares, and whether it sends any of them.
  struct FileHead {
    uint16_t status;
    size_t content_length;
    bool bodyless;
  };
  void file_spell(Conn& st, FileHead head);
  void file_prebuilt(Conn& st, uint16_t status_code);
  bool ws_upgrade(Conn& st, const WsUpgrade& up, std::string& sink);

  bool sse_begin(Conn& st, const SseBegin& req, std::string& sink);

  // RFC 7541 6.1/6.2.2: what a prebuilt block says - the status, the
  // Content-Type where the route has one, the Allow a 405 keeps.
  struct H2BlockFields {
    uint16_t status;
    const std::string* ctype = nullptr;
    const std::string* allow = nullptr;
  };
  void h2_build_block(H2Block& b, const H2BlockFields& f);
  bool h2_error_page(const H2ErrorAsk& a, H2ErrorPage& p, H2Answer& out);

  bool h2_begin(Conn& st, std::string& sink);
  bool h2_feed(Conn& st, std::string_view data, Sink out);
  bool h2_error(Conn& st, uint32_t code, std::string& sink);
  void h2_rst(Conn& st, uint32_t id, uint32_t code, std::string& sink);
  // RFC 9110 15.6.1: response.file has no HTTP/2 path yet - a run that
  // named one is refused rather than served the empty body it never meant
  // to send. Its own function because those fifteen lines are not part of
  // answering a stream, and inline they cost h2_answer 952 bytes.
  uint16_t h2_refuse_file(Conn& st, const ReqView* req);
  // RFC 9113 6.2: one HEADERS block as it arrived - the stream it belongs
  // to, whether the peer said that is the end of that stream, and the bytes
  // of the block itself.
  struct H2Headers {
    uint32_t stream_id;
    bool end_stream;
    std::span<const unsigned char> block;
  };
  bool h2_dispatch(Conn& st, const H2Headers& h, std::string& sink);
  // A parked stream's request as a view: the target it named, and the
  // ReqView the caller owns for it to point into.
  struct Parked {
    std::string_view target;
    ReqView& view;
    // Where the re-match writes its captures. The view only points at
    // them, so they have to live in the caller's frame, beside the view.
    RouteSpans& spans;
  };
  const ReqView* h2_parked_view(Conn& st, Parked p);
  // What one h2 access line is written from: the facts the stream carried,
  // and the :path they were read beside - which is still live only here.
  struct H2Logged {
    const flow::ReqFacts& facts;
    std::string_view target;
  };
  void h2_log(Conn& st, const H2Logged& l);
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
  // #30: the walk, and the framing, are two functions - a run can STOP
  // between them. One framer serves both paths.
  struct H2Produced;
  void h2_produce(Conn& st, const H2Request& q, bool can_park, H2Produced& p);
  void h2_after_run(Conn& st, const H2Request& q, H2Produced& p, uint16_t status);
  bool h2_answer(Conn& st, const H2Request& q, std::string& sink);
  bool h2_frame(Conn& st, const H2Request& q, std::string& sink, H2Produced& p);
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
  // The Webmachine::Config struct this app was configured through,
  // kept because app_mark_bound writes the bound listener back into
  // its url slot - conf.url reads the ask before the bind and the
  // truth after it. GC-registered at Application.new.
  mrb_value conf = mrb_nil_value();
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

// What a tool wants done under the VM's protection: the step, and what it
// needs to do it.
struct Guarded {
  int (*body)(mrb_state*, void*);
  void* ud;
};

// #33: a startup refuses by RAISING, and a raise is a C++ throw that needs
// a frame to land in. A tool's main is that frame, and this is how it
// spells one: the step runs, and what it refused with is printed and
// becomes a non-zero exit code. Printed, because a process that will not
// come up has no log to write into yet - and because stderr is read at
// exactly the moment a process dies.
int run_guarded(mrb_state* mrb, Guarded step);

void app_load(mrb_state* mrb, const char* path);

// Where every registered application goes, and how many listeners this
// build can carry - one more than that is a refusal, not a truncation.
struct Registered {
  std::vector<AppSpec*>& specs;
  size_t max_listeners;
};
void app_registered_all(mrb_state* mrb, Registered out);

AppSpec* app_assets_only();

void app_mark_bound(mrb_state* mrb, AppSpec& spec, const char* unix_path, int port);

void app_ready_run(mrb_state* mrb, AppSpec& spec);
}

namespace webmachine {
// server.docroot: the ONE directory response.file may reach, resolved to a
// canonical absolute path and opened O_DIRECTORY|O_PATH once at startup. That
// fd is what RESOLVE_BENEATH anchors against - the kernel does the
// confinement, this code never does path math of its own.
void docroot_open(mrb_state* mrb, const char* path);

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

void server_backend_say();

void server_init(mrb_state* mrb, struct RClass* wm);

int server_run(mrb_state* mrb);

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

void config_load(mrb_state* mrb, const char* path, Config& out);
}

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
// The file-descriptor budget one process has: what RLIMIT_NOFILE allows,
// and how many descriptors something other than a connection will take.
struct FdBudget {
  uint64_t nofile_limit;
  uint32_t extra_slots = 0;
};

inline uint32_t derive_max_conns(FdBudget b) {
  const uint64_t nofile_limit = b.nofile_limit;
  const uint32_t extra_slots = b.extra_slots;
  const uint64_t taken = static_cast<uint64_t>(kFdReserve) + kMaxListeners + extra_slots;
  if (nofile_limit <= taken) return 0;
  uint64_t n = nofile_limit - taken;
  if (n + kMaxListeners + extra_slots > kFixedTableKernelMax) {
    n = kFixedTableKernelMax - kMaxListeners - extra_slots;
  }
  return static_cast<uint32_t>(n);
}

// #80: jobs in flight per worker. Small on purpose - a compute task is work
// this process decided not to do on its core, and a deep queue in front
// of it only hides that every worker is already busy.
inline constexpr unsigned kComputeDepth = 16;
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
  kTlsTxKey = 20,
  // #80: a compute worker answered. The tag is the connection's, so the
  // generation guard every other op relies on discards an answer whose
  // connection is already gone.
  kComputeTask = 21
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
// #30: the same 8 bits for a compute job. A value round hands over
// several at one stop, so an answer has to say which one it is.
// Four bits name the stopped run and four name its job, so one byte
// carries both: a connection holds up to 16 stopped runs - one per h2
// stream - and a run hands over up to four jobs at a stop.
inline uint64_t compute_task_tag(uint16_t gen, uint32_t idx, uint8_t park, uint8_t job) {
  const uint8_t both = static_cast<uint8_t>((park << 4) | (job & 0x0f));
  return tag(kComputeTask, gen, idx) | (static_cast<uint64_t>(both) << 48);
}

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

}

#endif
