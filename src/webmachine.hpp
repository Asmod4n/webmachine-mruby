// Design decisions live in .DESIGN.md, filed under what each comment names.
#ifndef WEBMACHINE_HPP
#define WEBMACHINE_HPP

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/presym.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <liburing.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
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
#include <string>
#include <utility>
#include <vector>

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

struct Target {
  Node node;
  uint16_t status;
};
// The graph as data: an edge that continues to a node.
constexpr Target to(Node n) { return {n, 0}; }
// The graph as data: an edge that halts with a status.
constexpr Target halt(uint16_t s) { return {Node::kCount, s}; }

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

// Proof: an edge names a real node or a real status.
constexpr bool edge_valid(const Target& t) {
  if (t.status == 0) return t.node < Node::kCount;
  return t.status >= 100 && t.status <= 599;
}
// Proof: every edge of every node.
constexpr bool edges_valid() {
  for (size_t i = 0; i < kNodeCount; i++) {
    if (!edge_valid(kFlow[i].on_true) || !edge_valid(kFlow[i].on_false)) return false;
  }
  return true;
}
static_assert(edges_valid(), "every edge continues or halts");

// Proof: every path from here halts within the node count - no cycle.
constexpr bool terminates(Node n, size_t depth) {
  if (depth > kNodeCount) return false;
  const FlowNode& f = kFlow[static_cast<size_t>(n)];
  const bool t = f.on_true.status != 0 || terminates(f.on_true.node, depth + 1);
  const bool fl = f.on_false.status != 0 || terminates(f.on_false.node, depth + 1);
  return t && fl;
}
static_assert(terminates(Node::kB13, 0), "the flow is acyclic from B13");

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
enum class Method : uint8_t { kGet, kHead, kPost, kPut, kDelete, kOptions, kOther };

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
  bool plain = true;
  bool no_track = false;
};

struct KonstAnswers {
  bool ans[kNodeCount] = {};
};

// RFC 9110: the kRequest nodes - decided from the parsed request alone,
// never from the VM.
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
    default: return false;
  }
}

// RFC 9110: the graph, run with this request's facts and a resource's
// konst answers. Zero VM entries.
constexpr uint16_t walk(const ReqFacts& req, const KonstAnswers& k) {
  Node n = Node::kB13;
  for (;;) {
    const FlowNode& f = kFlow[static_cast<size_t>(n)];
    const bool ans =
        f.kind == Kind::kRequest ? eval_request(n, req) : k.ans[static_cast<size_t>(n)];
    const Target& t = ans ? f.on_true : f.on_false;
    if (t.status != 0) return t.status;
    n = t.node;
  }
}

struct Shortcut {
  uint16_t status = 0;
  bool always = false;
};

// Does any reachable node read the request? Explores BOTH branches at a
// kRequest node, since either may be taken.
constexpr bool any_request_node(Node n, const KonstAnswers& k, bool* seen) {
  if (seen[static_cast<size_t>(n)]) return false;
  seen[static_cast<size_t>(n)] = true;
  const FlowNode& f = kFlow[static_cast<size_t>(n)];
  if (f.kind == Kind::kRequest) return true;
  const Target& t = k.ans[static_cast<size_t>(n)] ? f.on_true : f.on_false;
  if (t.status != 0) return false;
  return any_request_node(t.node, k, seen);
}

// RFC 9110: what the graph would say when it has nothing to decide -
// from the SAME walk, run once with every header fact false.
constexpr Shortcut shortcut_for(Method m, const KonstAnswers& k) {
  Shortcut s;
  ReqFacts plain_facts;
  plain_facts.method = m;
  s.status = walk(plain_facts, k);
  bool seen[kNodeCount] = {};
  s.always = !any_request_node(Node::kB13, k, seen);
  return s;
}

// RFC 9110: the one entry point the request path calls. Two integer tests
// where the graph could not have said anything else.
constexpr uint16_t answer(const ReqFacts& req, const KonstAnswers& k, const Shortcut& s) {
  if (s.always || req.plain) return s.status;
  return walk(req, k);
}

namespace detail {
template <KonstAnswers K, Node N>
// RFC 9110: the compiled walk's one node, konst vector as a template
// parameter so the compiler folds it away.
constexpr uint16_t step(const ReqFacts& req) {
  constexpr FlowNode f = kFlow[static_cast<size_t>(N)];
  if constexpr (f.kind != Kind::kRequest) {
    constexpr Target t = K.ans[static_cast<size_t>(N)] ? f.on_true : f.on_false;
    if constexpr (t.status != 0) return t.status;
    else return step<K, t.node>(req);
  } else {
    if (eval_request(N, req)) {
      if constexpr (f.on_true.status != 0) return f.on_true.status;
      else return step<K, f.on_true.node>(req);
    } else {
      if constexpr (f.on_false.status != 0) return f.on_false.status;
      else return step<K, f.on_false.node>(req);
    }
  }
}
}

template <KonstAnswers K>
// RFC 9110: the compiled walk, measured against the interpreted one.
constexpr uint16_t walk_compiled(const ReqFacts& req) {
  return detail::step<K, Node::kB13>(req);
}

// RFC 9110: webmachine-ruby's Resource defaults, folded per method.
constexpr KonstAnswers default_konst(Method m) {
  KonstAnswers k{};
  const auto set = [&](Node n, bool v) { k.ans[static_cast<size_t>(n)] = v; };
  set(Node::kB13, true);
  set(Node::kB12, m != Method::kOther);
  set(Node::kB11, false);
  set(Node::kB10, m == Method::kGet || m == Method::kHead);
  set(Node::kB9a, true);
  set(Node::kB9b, false);
  set(Node::kB8, true);
  set(Node::kB7, false);
  set(Node::kB6, true);
  set(Node::kB5, true);
  set(Node::kB4, true);
  set(Node::kG7, true);
  set(Node::kC4, true);
  set(Node::kD5, true);
  set(Node::kE6, true);
  set(Node::kF7, true);
  set(Node::kL17, true);
  set(Node::kM20b, true);
  set(Node::kO18, true);
  set(Node::kO18b, false);
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
    for (uint8_t m = 0; m < 7; m++) per_method[m] = default_konst(static_cast<Method>(m));
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
  k.ans[static_cast<size_t>(Node::kB10)] = true;
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
  k.ans[static_cast<size_t>(Node::kG7)] = false;
  return k;
}();
static_assert(walk(im_star_missing, missing) == 412,
              "If-Match: * against a missing resource is 412 (H7)");
static_assert(walk(get_plain, missing) == 404,
              "GET on a never-existed resource is 404 (L7)");
static_assert(walk_compiled<default_konst(Method::kGet)>(get_plain) == 200);
static_assert(walk_compiled<default_konst(Method::kDelete)>(del) == 405);
static_assert(walk_compiled<default_konst(Method::kGet)>(inm_star) == 304);
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
struct Logger {
  bool enabled = false;
  std::string buf;
  std::string flight;
  bool in_flight = false;
  int64_t sec = 0;
};

struct LogRec {
  uint8_t version;
  uint8_t flags;
  uint16_t status;
  uint32_t bytes;
  int64_t sec;
  uint8_t mlen;
  uint8_t plen;
  uint16_t tlen;
  uint16_t rlen;
  uint16_t ulen;
};
inline constexpr uint8_t kLogRecVersion = 3;
inline constexpr uint8_t kLogH2 = 1;
inline constexpr uint8_t kLogNoTrack = 2;

// Combined Log Format: one response as one record. Truncation caps are the
// wire fields' widths.
inline void log_access(Logger& lg, const void* peer, size_t plen, const char* method, size_t mlen,
                       const char* target, size_t tlen, uint8_t flags, uint16_t status,
                       size_t body_bytes, const char* ref, size_t rlen, const char* ua,
                       size_t ulen) {
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
  r.sec = lg.sec;
  r.mlen = static_cast<uint8_t>(mlen);
  r.plen = static_cast<uint8_t>(plen);
  r.tlen = static_cast<uint16_t>(tlen);
  r.rlen = static_cast<uint16_t>(rlen);
  r.ulen = static_cast<uint16_t>(ulen);
  lg.buf.append(reinterpret_cast<const char*>(&r), sizeof r);
  if (mlen != 0) lg.buf.append(method, mlen);
  if (plen != 0) lg.buf.append(static_cast<const char*>(peer), plen);
  if (tlen != 0) lg.buf.append(target, tlen);
  if (rlen != 0) lg.buf.append(ref, rlen);
  if (ulen != 0) lg.buf.append(ua, ulen);
}

struct ErrRec {
  uint8_t version;
  uint8_t flags;
  uint16_t status;
  int64_t sec;
  uint8_t plen;
  uint8_t klen;
  uint16_t tlen;
  uint16_t mlen;
  uint16_t blen;
  uint32_t dyn;
};
inline constexpr uint8_t kErrRecVersion = 1;

// One raise as one record: a FIXED header whose last field is the size of
// the second send, then that many bytes.
inline void log_error(Logger& lg, const void* peer, size_t plen, const char* klass, size_t klen,
                      const char* target, size_t tlen, uint16_t status, const char* mesg,
                      size_t mlen, const char* trace, size_t blen) {
  if (plen > 255) plen = 255;
  if (klen > 255) klen = 255;
  if (tlen > 65535) tlen = 65535;
  if (mlen > 65535) mlen = 65535;
  if (blen > 65535) blen = 65535;
  ErrRec r;
  r.version = kErrRecVersion;
  r.flags = 0;
  r.status = status;
  r.sec = lg.sec;
  r.plen = static_cast<uint8_t>(plen);
  r.klen = static_cast<uint8_t>(klen);
  r.tlen = static_cast<uint16_t>(tlen);
  r.mlen = static_cast<uint16_t>(mlen);
  r.blen = static_cast<uint16_t>(blen);
  r.dyn = static_cast<uint32_t>(plen + klen + tlen + mlen + blen);
  lg.buf.append(reinterpret_cast<const char*>(&r), sizeof r);
  if (plen != 0) lg.buf.append(static_cast<const char*>(peer), plen);
  if (klen != 0) lg.buf.append(klass, klen);
  if (tlen != 0) lg.buf.append(target, tlen);
  if (mlen != 0) lg.buf.append(mesg, mlen);
  if (blen != 0) lg.buf.append(trace, blen);
}

// One raise as one error record. Defined in resource.cpp - it needs a VM.
void log_exception(Logger& lg, mrb_state* mrb, const void* peer, size_t plen, const char* target,
                   size_t tlen, uint16_t status);
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

// RFC 9110 5.6.7: IMF-fixdate by hand - strftime would obey the locale.
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
};

enum class RangeParse : uint8_t { kNone, kOne, kUnsat };
// RFC 9110 14.1.2: ONE range over the SELECTED representation's octets.
// kNone means act as if the field were absent (14.2 permits it).
inline RangeParse parse_range(const char* v, size_t n, size_t complete, size_t* first,
                              size_t* last) {
  if (n < 7 || !tok_eq(v, 6, "bytes=", 6)) return RangeParse::kNone;
  size_t i = 6;
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  const auto digits = [&](size_t* out) -> bool {
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

template <class OnWire>
// RFC 9110: ONE length-switch per header. The 9110 facts are filled here;
// every name this layer does not own falls through to the framer's functor.
inline void header_switch(const char* name, size_t nlen, const char* value, size_t vlen,
                          flow::ReqFacts& facts, ReqValues& vals, OnWire&& wire) {
  switch (nlen) {
    case 3:
      if (tok_eq(name, nlen, "dnt", 3)) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return;
      }
      break;
    case 5:
      if (tok_eq(name, nlen, "range", 5)) {
        vals.range = value;
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
      if (tok_eq(name, nlen, "sec-gpc", 7)) {
        if (vlen == 1 && value[0] == '1') facts.no_track = true;
        return;
      }
      break;
    case 8:
      if (tok_eq(name, nlen, "if-range", 8)) {
        vals.if_range = value;
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
        facts.has_if_modified_since = true;
        facts.plain = false;
        return;
      }
      break;
    case 19:
      if (tok_eq(name, nlen, "if-unmodified-since", 19)) {
        facts.has_if_unmodified_since = true;
        facts.plain = false;
        return;
      }
      break;
    default:
      break;
  }
  wire(name, nlen, value, vlen);
}
}

namespace webmachine {
struct ReqView {
  const char* target = nullptr;
  size_t target_len = 0;
  size_t path_len = 0;
  flow::Method method = flow::Method::kGet;
  const char* method_p = nullptr;
  size_t method_n = 0;
  const RouteTable* table = nullptr;
  int route = -1;
  RouteSpans spans {};
  const void* hdrs = nullptr;
  size_t nhdr = 0;
};

void request_init(mrb_state* mrb, struct RClass* wm);

void request_bind(const ReqView* view);
}

namespace webmachine {
struct Resource {
  flow::KonstSet konst;
  mrb_state* mrb = nullptr;
  struct RClass* klass = nullptr;
  uint64_t dynamic = 0;
  mrb_sym node_sym[flow::kNodeCount] = {};
  mrb_method_t node_m[flow::kNodeCount] = {};
  bool node_fast[flow::kNodeCount] = {};
  bool dynamic_body = false;
  mrb_sym body_sym = {};
  mrb_method_t body_m = {};
  bool body_fast = false;
  bool gzip_offered = false;
  mrb_value run_self = {};
  mutable mrb_value live = {};
  mutable const flow::ReqFacts* run_facts = nullptr;
  mutable std::string* run_body = nullptr;
  mutable bool run_have_body = false;
  mutable uint16_t run_status = 0;
};

bool resource_fold(mrb_state* mrb, mrb_value klass, Resource& out, char* err, size_t errlen);

uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, const ReqView* req,
                      std::string* body, bool* have_body);

bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);
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

struct AssetEntry {
  std::string name;
  const char* data = nullptr;
  size_t comp_size = 0;
  size_t uncomp_size = 0;
  uint32_t crc = 0;
  bool deflated = false;
  bool lm_valid = false;
  char etag[10] = {};
  char lm[http::kDateLen] = {};
  std::string ctype;

  struct Resp {
    std::string bytes;
    size_t date_off = 0;
    time_t sec = 0;
  };
  Resp h200[3];
  Resp h304[3];

  unsigned char gz_hdr[10] = {};
  unsigned char gz_trailer[8] = {};

  std::string h2_200;
  std::string h2_304;
};

class Assets {
 public:
  enum Variant : uint8_t { kPlain = 0, kKeep = 1, kClose = 2 };
  static constexpr const char* kConn[3] = {"", "Connection: keep-alive\r\n",
                                           "Connection: close\r\n"};

  Assets() = default;
  ~Assets();
  Assets(const Assets&) = delete;
  Assets& operator=(const Assets&) = delete;

  bool open(const char* zip_path, const MimeDb& mime, char* err, size_t errlen);

  AssetEntry* find(const char* path, size_t len);

  uint16_t verdict(const AssetEntry& e, flow::Method m, const flow::ReqFacts& f,
                   const http::ReqValues& vals) const;

  void answer_head(AssetEntry& e, uint16_t status, Variant v, const char* date, time_t sec,
                   std::string& sink);

  void answer_206_head(const AssetEntry& e, Variant v, size_t first, size_t last,
                       const char* date, std::string& sink);
  void answer_416_head(const AssetEntry& e, Variant v, const char* date, std::string& sink);

  // RFC 1952: the wire body's length - deflate plus 18 framing bytes, or
  // the stored bytes alone.
  static size_t wire_len(const AssetEntry& e) {
    return e.deflated ? e.comp_size + 18 : e.comp_size;
  }
  static unsigned wire_iov(const AssetEntry& e, size_t off, size_t n, struct iovec* iov);
  static void copy_wire(const AssetEntry& e, size_t off, size_t n, std::string& sink);

  // ZIP (APPNOTE): the entry table, for the h2 setup half.
  std::vector<AssetEntry>& entries() { return entries_; }

 private:
  static void patch_date(AssetEntry::Resp& r, const char* date, time_t sec);

  const char* map_ = nullptr;
  size_t map_len_ = 0;
  std::vector<AssetEntry> entries_;
  AssetEntry::Resp s405_[3];
  AssetEntry::Resp s406_[3];
};
}

#include "lshpack.h"

namespace webmachine {
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

enum : uint8_t {
  kH2FlagEndStream = 0x1,
  kH2FlagAck = 0x1,
  kH2FlagEndHeaders = 0x4,
  kH2FlagPadded = 0x8,
  kH2FlagPriority = 0x20,
};

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

enum : uint16_t {
  kH2SettingsHeaderTableSize = 0x1,
  kH2SettingsEnablePush = 0x2,
  kH2SettingsMaxConcurrentStreams = 0x3,
  kH2SettingsInitialWindowSize = 0x4,
  kH2SettingsMaxFrameSize = 0x5,
};

inline constexpr char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr size_t kH2PrefaceLen = 24;
inline constexpr size_t kH2PrefaceAnnounce = 18;

inline constexpr size_t kH2FrameHeaderLen = 9;
inline constexpr uint32_t kH2MaxFrameSize = 16384;
inline constexpr int64_t kH2DefaultWindow = 65535;
inline constexpr uint32_t kH2MaxConcurrentStreams = 256;
inline constexpr int64_t kH2WindowCeiling = 0x7fffffff;

// RFC 9113 4.1: the 9-byte frame header; stream id at offset 5.
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

// RFC 9113 4.1: the 4 stream-id bytes of an already-emitted frame header.
inline void h2_patch_stream_id(unsigned char* p, uint32_t stream) {
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

// RFC 9113 4.1: a frame's length field.
inline uint32_t h2_u24(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}
// RFC 9113 4.1: a 32-bit field, network order.
inline uint32_t h2_u32(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
// RFC 9113 4.1: a stream id, reserved bit masked off.
inline uint32_t h2_u31(const unsigned char* p) { return h2_u32(p) & 0x7fffffff; }
// RFC 9113 6.5.1: a settings identifier.
inline uint16_t h2_u16(const unsigned char* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

struct AssetEntry;

struct H2Stream {
  uint32_t id = 0;
  int64_t send_window = kH2DefaultWindow;
  size_t body_len = 0;
  size_t content_length = 0;
  bool have_content_length = false;
  std::string pending;
  flow::ReqFacts facts;
  const AssetEntry* asset = nullptr;
  uint16_t asset_status = 0;
  size_t asset_off = 0;
  size_t asset_end = 0;
  const AssetEntry* src = nullptr;
  size_t src_off = 0;
  size_t src_len = 0;
  uint16_t route = 0;
  std::string target;
  bool head_only = false;
  bool headers_done = false;
  bool half_closed_remote = false;
};

struct H2State {
  struct lshpack_enc enc;
  struct lshpack_dec dec;

  int64_t send_window = kH2DefaultWindow;
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

  struct {
    std::string bytes;
    size_t head_len = 0;
    bool has_data = false;
    uint16_t status = 0;
    uint16_t route = 0xffff;
    time_t sec = 0;
  } head_cache;

  // RFC 9113: allocated only when the preface was spoken, never before.
  H2State() {
    lshpack_enc_init(&enc);
    lshpack_dec_init(&dec);
  }
  // RFC 9113: the decoder dies with the connection.
  ~H2State() {
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
    st.send_window = peer_initial_window;
    return st;
  }
  // RFC 9113 5.1: the number stays, the entry goes.
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

class Codec {
 public:
  Codec() = default;
  Codec(const Codec&) = delete;
  Codec& operator=(const Codec&) = delete;
  // RFC 7692: both zlib streams die with the connection.
  ~Codec() {
    if (inf_on_) inflateEnd(&inf_);
    if (def_on_) deflateEnd(&def_);
  }

  // RFC 7692 7.1.2: what the negotiation settled on.
  void configure(const Params& p) { p_ = p; }
  // RFC 7692: what this connection agreed to.
  const Params& params() const { return p_; }

  template <class Sink>
  // RFC 7692 7.2.2: payload bytes as they arrive; the SINK is the only
  // bound, which is the whole decompression-bomb answer.
  int inflate_some(const char* in, size_t n, Sink&& sink) {
    if (!inflate_ready()) return -1;
    inf_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
    inf_.avail_in = static_cast<uInt>(n);
    return pump(sink);
  }

  template <class Sink>
  // RFC 7692 7.2.2 step 1: the four bytes the sender stripped go back on.
  int inflate_finish(Sink&& sink) {
    if (!inflate_ready()) return -1;
    inf_.next_in = const_cast<Bytef*>(kSyncTail);
    inf_.avail_in = sizeof(kSyncTail);
    const int rc = pump(sink);
    if (rc != 0) return rc;
    if (p_.client_no_context_takeover || inf_ended_) {
      inflateReset(&inf_);
      inf_ended_ = false;
    }
    return 0;
  }

  // RFC 7692 7.2.1: one whole message; false means send it uncompressed,
  // and then never compress on this connection again.
  bool compress(const char* in, size_t n, std::string& out) {
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
      if (def_.avail_out != 0) break;
    }
    if (out.size() < sizeof(kSyncTail) ||
        std::memcmp(out.data() + out.size() - sizeof(kSyncTail), kSyncTail,
                    sizeof(kSyncTail)) != 0) {
      def_broken_ = true;
      return false;
    }
    out.resize(out.size() - sizeof(kSyncTail));
    if (p_.server_no_context_takeover) deflateReset(&def_);
    return true;
  }

 private:
  // RFC 7692 7.1.2.1: never below 9 bits - no zlib can produce an 8-bit
  // window, and larger than promised is always safe.
  bool inflate_ready() {
    if (inf_on_) return true;
    const int bits = p_.client_max_window_bits < kMinRawWindowBits
                         ? kMinRawWindowBits
                         : p_.client_max_window_bits;
    if (inflateInit2(&inf_, -bits) != Z_OK) return false;
    inf_on_ = true;
    return true;
  }

  // RFC 7692 7.1.2.1: raw deflate, the negotiated window, Z_BEST_SPEED.
  bool deflate_ready() {
    if (def_on_) return true;
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
  // RFC 7692 7.2.2: inflate until zlib stops producing.
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
      if (inf_.avail_out != 0) return 0;
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

struct Frame {
  uint8_t opcode = 0;
  bool fin = false;
  bool rsv1 = false;
  const char* payload = nullptr;
  size_t len = 0;
  size_t consumed = 0;
};

enum class Parse : uint8_t {
  kOk,
  kNeedMore,
  kError,
};

Parse parse(char* data, size_t len, size_t max_payload, bool allow_rsv1, Frame& out,
            uint16_t& code);

size_t build_header(uint8_t opcode, bool fin, bool rsv1, size_t payload_len, char head[10]);

size_t build_close_payload(uint16_t code, const char* reason, size_t reason_len,
                           char out[125]);

bool read_close(const char* payload, size_t len, uint16_t& code, const char** reason,
                size_t* reason_len);
}
}

namespace webmachine {
struct Resource;
struct ReqView;
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, const ReqView* req,
                      std::string* body, bool* have_body);
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len);

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
inline constexpr size_t kMaxBody = 1u << 20;
inline constexpr size_t kMaxHeaders = 64;
inline constexpr size_t kCompressFloor = 1280;
inline constexpr size_t kDeliverChunk = 64u * 1024;

inline constexpr size_t kWarmBudgetDefault = kDeliverChunk;

inline constexpr uint16_t kNoRoute = 0xffff;

class Http1 {
 public:
  struct Conn {
    std::string carry;
    size_t body_skip = 0;
    uint8_t listener = 0;
    bool fresh = true;
    H2State* h2 = nullptr;
    const AssetEntry* xfer = nullptr;
    size_t xfer_off = 0;
    size_t xfer_end = 0;
    bool packetized = false;
    WsConn* ws = nullptr;
    SseStream* sse = nullptr;
    const void* peer = nullptr;
    uint8_t peer_len = 0;
    // The Ring resets this; `li` is the App's key to "whose connection is
    // this", `pkt` says whether that listener is TCP.
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
    // The websocket, the stream and the h2 state die with the connection.
    ~Conn() {
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

  void on_tick();

  bool pending(const Conn& st) const;

  // WHATWG HTML: does this connection carry a source with its own schedule?
  bool timed(const Conn& st) const { return st.sse != nullptr; }

  struct Plan {
    struct Seg {
      const char* base;
      size_t off;
      size_t len;
    };
    static constexpr unsigned kSegs = 1023;
    Seg seg[kSegs];
    unsigned nseg = 0;
    size_t iov_len = 0;
    size_t byte_cap = 0;
  };

  bool feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan);

  bool more(Conn& st, std::string& sink, Plan& plan);

  // The App FORMATS lines; the Ring flushes the buffer. Opt-in.
  Logger* access_log() { return &alog_; }
  // The only way an access line is ever built.
  void enable_access_log() { alog_.enabled = true; }
  // The second stream: its own socket, its own daemon, its own file.
  Logger* error_log() { return &elog_; }
  // The only way an error record is ever built.
  void enable_error_log() { elog_.enabled = true; }

 private:
  struct AppSlot;

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

  struct Bundle {
    flow::KonstSet konst;
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
  void build_status(uint16_t status, const char* extra, const char* body);
  void build_bundle(Bundle& b, const Resource* res);
  static void patch_date(Variants& v, const char* core);
  static void assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                       bool head_only);
  void assemble_dynamic(const Conn& st, const flow::ReqFacts& facts, const http::ReqValues& vals,
                        const Resp& prefix_id, const Resp& prefix_gz, bool head_only,
                        std::string& sink);
  // RFC 9112 9.3: one prebuilt status in its three connection spellings.
  const Variants& variants(uint16_t status) const {
    return store_[index_[status]];
  }
  bool fail(Conn& st, uint16_t status, std::string& sink, uint8_t log_flags = 0);
  bool ws_upgrade(Conn& st, const AppSlot& slot, int route, const char* path, size_t path_len,
                  const RouteSpans& spans, const char* key, size_t key_len, const void* hdrs,
                  size_t nhdr, const char* rest, size_t rest_len, std::string& sink);

  bool sse_begin(Conn& st, const AppSlot& slot, int route, const char* method,
                 size_t method_len, const char* path, size_t path_len,
                 const RouteSpans& spans, const void* hdrs, size_t nhdr, int minor,
                 flow::Method m, const http::ReqValues& vals, uint8_t lflags,
                 std::string& sink);

  void h2_build_block(H2Block& b, uint16_t status, const std::string* ctype,
                      const std::string* allow);
  static bool h2_enc_field(void* enc, unsigned char*& ep, unsigned char* eend,
                           const char* name, size_t nlen, const char* val, size_t vlen);

  bool h2_begin(Conn& st, std::string& sink);
  bool h2_feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan);
  bool h2_error(Conn& st, uint32_t code, std::string& sink);
  void h2_rst(Conn& st, uint32_t stream_id, uint32_t code, std::string& sink);
  bool h2_dispatch(Conn& st, uint32_t stream_id, bool end_stream, std::string& sink);
  const ReqView* h2_parked_view(Conn& st, const std::string& target, ReqView& out);
  void h2_log(Conn& st, const flow::ReqFacts& facts, const char* target, size_t tlen);
  bool h2_answer(Conn& st, uint32_t stream_id, const flow::ReqFacts& facts, bool head_only,
                 uint16_t route, const ReqView* req, std::string& sink);
  void h2_flush_pending(Conn& st, std::string& sink, Plan* plan);
  void h2_build_asset_blocks(AssetEntry& e);
  void h2_build_asset_shared();
  bool h2_asset_answer(Conn& st, uint32_t stream_id, const AssetEntry& e, uint16_t status,
                       bool head_only, size_t win_off, size_t win_end, std::string& sink);

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
  std::array<uint16_t, 600> index_ {};
  std::vector<H2Block> h2_store_;
  H2Block h2_asset405_;
  H2Block h2_asset406_;
  Assets* assets_ = nullptr;
  size_t warm_budget_ = kWarmBudgetDefault;
  Logger alog_;
  Logger elog_;
  uint16_t alog_status_ = 0;
  size_t alog_bytes_ = 0;
  std::string body_;
  std::string gz_body_;
  char date_[29] = {};
};
}

namespace webmachine {
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
};

void application_init(mrb_state* mrb, struct RClass* wm);

bool app_load(mrb_state* mrb, const char* path, char* err, size_t errlen);

bool app_registered_all(std::vector<AppSpec*>& out, size_t max_listeners, char* err,
                        size_t errlen);

AppSpec* app_default();

void app_mark_bound(AppSpec& spec, const char* unix_path, int port);

bool app_ready_run(mrb_state* mrb, AppSpec& spec, char* err, size_t errlen);
}

namespace webmachine {
struct ServerOptions {
  const char* assets_path = nullptr;
  const char* mime_path = nullptr;
  const char* log_path = nullptr;
  const char* log_privacy = nullptr;
  const char* error_log_path = nullptr;
  unsigned long long log_max_bytes = 500ull * 1024 * 1024;
  int stop_fd = -1;
  const char* cli_unix = nullptr;
  int cli_port = 0;
  const char* app_path = nullptr;
  bool have_uring = false;
  unsigned sq_entries = 0;
  int backlog = 0;
  int to_header = 0;
  int to_send = 0;
  int to_idle = 0;
};
void server_options(const ServerOptions& opts);

bool server_backend_ok(bool have_uring, char* err, size_t errlen);

void server_init(mrb_state* mrb, struct RClass* wm);

int server_run(mrb_state* mrb, char* err, size_t errlen);

bool server_entered();
}

namespace webmachine {
struct Config {
  std::string path;

  std::string unix_path;
  int port = 0;
  std::string app;
  std::string assets;
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
};

struct RingConfig {
  ListenerSpec listeners[kMaxListeners] = {};
  uint32_t nlisteners = 0;
  int log_fd = -1;
  int err_fd = -1;
  unsigned sq_entries = 0;
  int backlog = 0;
  int to_header = 0;
  int to_send = 0;
  int to_idle = 0;
  int stop_fd = -1;
};

namespace detail {
enum : uint8_t {
  kAccept = 1, kRecv = 2, kSend = 3, kClose = 4, kSetup = 5, kStop = 6, kShutdown = 7,
  kMeminfo = 8, kLog = 9, kPeer = 10
};

// user_data: kind(8) | gen(16) | idx(32); gen guards a reused slot.
inline uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
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
    }
    nlisteners_ = cfg.nlisteners;

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
        int slen = static_cast<int>(sizeof(ss));
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
        io_uring_prep_rw(IORING_OP_URING_CMD, s, static_cast<int>(slot), nullptr, 0, 0);
        s->cmd_op = SOCKET_URING_OP_GETSOCKNAME;
        s->addr = reinterpret_cast<uint64_t>(&ss);
        s->optval = reinterpret_cast<uint64_t>(&slen);
        s->optlen = 0;
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
    bool live = false;
    bool sending = false;
    bool close_after_send = false;
    bool idle = false;
    int64_t deadline_s = 0;
    uint8_t li = 0;
    uint16_t gen = 0;
    size_t sent = 0;

    static constexpr size_t kRoundFloor = 64u * 1024;
    size_t round_cap = kRoundFloor;
    uint32_t mi[SK_MEMINFO_VARS] = {};
    struct sockaddr_storage peer_ss;
    int peer_slen = 0;

    std::string out;
    std::string next;

    static constexpr unsigned kIov = App::Plan::kSegs + 1;
    unsigned niov = 0;
    size_t plan_len = 0;
    struct msghdr msg {};

    typename App::Conn app;

    std::unique_ptr<struct iovec[]> iov;
    std::unique_ptr<struct iovec[]> msg_iov;
  };

  // Never null: a full SQ is submitted and retried once, and a ring that
  // still cannot take an SQE is a broken ring.
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
    if (al == nullptr || al->in_flight || al->buf.empty()) return;
    al->buf.swap(al->flight);
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
    if (el == nullptr || el->in_flight || el->buf.size() < sizeof(ErrRec)) return;
    ErrRec r;
    std::memcpy(&r, el->buf.data(), sizeof r);
    const size_t whole = sizeof(ErrRec) + r.dyn;
    if (el->buf.size() < whole) return;
    el->flight.assign(el->buf, 0, whole);
    el->buf.erase(0, whole);
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
      std::fprintf(stderr, "webmachine: %s log write failed: %s - refusing to drop lines\n",
                   stream == kStreamError ? "error" : "access", std::strerror(-cqe->res));
      std::exit(1);
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

  // Multishot recv out of the buffer ring, bundles where the kernel offers them.
  void arm_recv(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
    s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    s->buf_group = kBufGroup;
    if (bundles_) s->ioprio |= IORING_RECVSEND_BUNDLE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
  }

  // One sendmsg for the whole round; MSG_MORE when the App still owes bytes.
  void arm_send(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    const int flags = MSG_NOSIGNAL | (app_.pending(c.app) ? MSG_MORE : 0);
    if (c.niov == 0) {
      io_uring_prep_send(s, static_cast<int>(idx), c.out.data() + c.sent,
                         c.out.size() - c.sent, flags);
    } else {
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

  // shutdown BEFORE close_direct, linked: close_direct alone leaves the
  // socket open and the peer never sees FIN.
  void begin_close(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.live) return;
    if (c.sending) {
      c.close_after_send = true;
      return;
    }
    c.live = false;
    if (live_ != 0) live_--;
    if (io_uring_sq_space_left(&ring_) < 2) io_uring_submit(&ring_);
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
    live_++;
    c.sending = false;
    c.close_after_send = false;
    c.idle = false;
    c.deadline_s = now_s_ + to_header_;
    c.li = static_cast<uint8_t>(li);
    c.sent = 0;
    c.out.clear();
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
    arm_meminfo(idx);
    if (log_fd_ >= 0 && !unix_listener_[li]) arm_peer(idx);
    arm_recv(idx);
  }

  // Wire bytes to the App. Kernel-supplied ids and lengths are checked
  // before use; ENOBUFS re-arms rather than hanging the connection.
  void on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;

    if (WM_UNLIKELY(cqe->res <= 0)) {
      if (cqe->res == -ENOBUFS) {
        rearm_.push_back(idx);
        return;
      }
      begin_close(idx);
      return;
    }
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
    if (WM_UNLIKELY(bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize)) {
      begin_close(idx);
      return;
    }

    if (WM_UNLIKELY(c.close_after_send)) {
      replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
      return;
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
      if (req.nseg != 0) {
        take_plan(c, req);
        arm_send(idx);
      } else if (!c.out.empty()) {
        arm_send(idx);
      }
    }
    if (WM_UNLIKELY(closing)) {
      if (c.sending) c.close_after_send = true;
      else begin_close(idx);
      return;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
  }

  // What the kernel took, and what is still owed.
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
    const size_t offered = c.niov != 0 ? c.plan_len : c.out.size();
    size_t new_sent = 0;
    if (WM_UNLIKELY(took > offered - c.sent ||
                    __builtin_add_overflow(c.sent, took, &new_sent))) {
      begin_close(idx);
      return;
    }
    c.sent = new_sent;
    c.deadline_s = now_s_ + to_send_;
    if (c.sent < offered) {
      arm_send(idx);
      return;
    }
    c.out.clear();
    c.sent = 0;
    c.niov = 0;
    c.plan_len = 0;
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

  // SO_MEMINFO through the ring - SOL_SOCKET is the only level it allows.
  void arm_meminfo(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_GETSOCKOPT, static_cast<int>(idx), SOL_SOCKET,
                           SO_MEMINFO, c.mi, sizeof(c.mi));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kMeminfo, c.gen, idx));
  }

  // SOCKET_URING_OP_GETSOCKNAME, peer form, spelled by hand against
  // cmd_net.c's contract. Only when someone is logging.
  void arm_peer(uint32_t idx) {
    Conn& c = conns_[idx];
    c.peer_slen = static_cast<int>(sizeof(c.peer_ss));
    struct io_uring_sqe* s = sqe();
    io_uring_prep_rw(IORING_OP_URING_CMD, s, static_cast<int>(idx), nullptr, 0, 0);
    s->cmd_op = SOCKET_URING_OP_GETSOCKNAME;
    s->addr = reinterpret_cast<uint64_t>(&c.peer_ss);
    s->optval = reinterpret_cast<uint64_t>(&c.peer_slen);
    s->optlen = 1;
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
    if (c.peer_slen > 0 && static_cast<size_t>(c.peer_slen) <= sizeof(c.peer_ss)) {
      c.app.peer = &c.peer_ss;
      c.app.peer_len = static_cast<uint8_t>(
          c.peer_slen > 255 ? 255 : c.peer_slen);
    }
  }

  // The round's byte bound, from the socket's own books.
  void on_meminfo(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    size_t cap = Conn::kRoundFloor;
    if (WM_LIKELY(cqe->res >= 0)) {
      const uint32_t used = c.mi[SK_MEMINFO_WMEM_QUEUED] > c.mi[SK_MEMINFO_WMEM_ALLOC]
                                ? c.mi[SK_MEMINFO_WMEM_QUEUED]
                                : c.mi[SK_MEMINFO_WMEM_ALLOC];
      const uint32_t buf = c.mi[SK_MEMINFO_SNDBUF];
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
    c.idle = true;
    c.deadline_s = now_s_ + to_idle_;
  }
  // One completion, by tag.
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
      case detail::kStop: stop_ = true; break;
      default: break;
    }
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
      for (uint32_t i = 0; i < max_conns_; i++) {
        Conn& c = conns_[i];
        if (!c.live) continue;
        if (!c.sending && app_.timed(c.app)) {
          c.deadline_s = now_s_ + to_idle_;
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
  int log_fd_ = -1;
  int err_fd_ = -1;
  unsigned sq_entries_ = 0;
  int backlog_ = 511;
  int to_header_ = 60;
  int to_send_ = 60;
  int to_idle_ = 75;
  int64_t now_s_ = 0;
  int64_t last_reap_s_ = 0;
  uint32_t max_conns_ = 0;
  uint32_t listener_base_ = 0;
  bool unix_listener_[kMaxListeners] = {};
  int bound_port_[kMaxListeners] = {};
  std::vector<std::string> unix_paths_;
  uint32_t nlisteners_ = 0;
  bool listeners_closed_ = false;
  bool draining_ = false;
  int64_t drain_deadline_ = 0;
  uint32_t live_ = 0;
  char* pool_ = nullptr;
  struct io_uring_buf_ring* buf_ring_ = nullptr;
  unsigned replenish_ = 0;
  std::vector<Conn> conns_;
  std::vector<uint32_t> rearm_;
};
}

#endif
