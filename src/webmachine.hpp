#ifndef WEBMACHINE_HPP
#define WEBMACHINE_HPP

#include <array>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
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
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <zlib.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <coroutine>
#include <cstring>
#include <ctime>
#include <limits>
#include <functional>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

// openat2(2) is the docroot confinement that response.file rests on.
// An older toolchain gets the kernel's own values from linux/openat2.h.
// All three RESOLVE_ flags, always: BENEATH stops ".." and absolute
// paths, NO_SYMLINKS stops a symlink inside the docroot that points out,
// NO_MAGICLINKS stops the /proc-style ones.
// mrb_noreturn resolves to nothing under -std=c++20, so a function that
// ends in a raise needs WM_UNREACHABLE().
#if defined(_MSC_VER) && !defined(__clang__)
#define WM_UNREACHABLE() __assume(0)
#else
#define WM_UNREACHABLE() __builtin_unreachable()
#endif

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

struct phr_header;

namespace webmachine::flow
{
// The node names are the letters of Alan Dean and Justin Sheehy's HTTP decision diagram.
enum class Node : uint8_t {
    kB13,
    kB12,
    kB11,
    kB10,
    kB9b,
    kB8,
    kB7,
    kB6,
    kB5,
    kB4,
    kB3,
    kC3,
    kC4,
    kD4,
    kD5,
    kE5,
    kE6,
    kF6,
    kF7,
    kG7,
    kG8,
    kG9,
    kG11,
    kH7,
    kH10,
    kH11,
    kH12,
    kI4,
    kI7,
    kI12,
    kI13,
    kJ18,
    kK5,
    kK7,
    kK13,
    kL5,
    kL7,
    kL13,
    kL14,
    kL15,
    kL17,
    kM5,
    kM7,
    kM16,
    kM20,
    kM20b,
    kN5,
    kN11,
    kN16,
    kO14,
    kO16,
    kO18,
    kO18b,
    kO20,
    kP3,
    kP11,
    kCount
};

// RFC 9110 has no such split. It lets a kRequest node answer without the VM.
enum class Kind : uint8_t { kRequest, kResource, kConneg, kAction };

struct Target {
    Node node;
    uint16_t status;
};
constexpr Target to(Node count)
{
    return {count, 0};
}
constexpr Target halt(uint16_t sqe)
{
    return {Node::kCount, sqe};
}

// `callback` is webmachine-ruby's method name, verbatim: an app writes against it.
// `clause` is the RFC 9110 section the edge implements.
struct FlowNode {
    Node id;
    Kind kind;
    const char *callback;
    const char *clause;
    Target on_true;
    Target on_false;
};

inline constexpr FlowNode kFlow[] = {
    {Node::kB13, Kind::kResource, "service_available?", "RFC 9110 15.6.4 (503)", to(Node::kB12),
     halt(503)},
    {Node::kB12, Kind::kResource, "known_methods", "RFC 9110 15.6.2 (501); list x method",
     to(Node::kB11), halt(501)},
    {Node::kB11, Kind::kResource, "uri_too_long?", "RFC 9110 15.5.15 (414)", halt(414),
     to(Node::kB10)},
    {Node::kB10, Kind::kResource, "allowed_methods", "RFC 9110 15.5.6 (405) + 10.2.1 Allow",
     to(Node::kB9b), halt(405)},
    {Node::kB9b, Kind::kResource, "malformed_request?", "RFC 9110 15.5.1 (400)", halt(400),
     to(Node::kB8)},
    {Node::kB8, Kind::kResource, "is_authorized?",
     "RFC 9110 15.5.2 (401) + 11.6.1 WWW-Authenticate", to(Node::kB7), halt(401)},
    {Node::kB7, Kind::kResource, "forbidden?", "RFC 9110 15.5.4 (403)", halt(403), to(Node::kB6)},
    {Node::kB6, Kind::kResource, "valid_content_headers?", "RFC 9110 15.6.2 (501); Content-* set",
     to(Node::kB5), halt(501)},
    {Node::kB5, Kind::kResource, "known_content_type?", "RFC 9110 15.5.16 (415)", to(Node::kB4),
     halt(415)},
    {Node::kB4, Kind::kResource, "valid_entity_length?", "RFC 9110 15.5.14 (413)", to(Node::kB3),
     halt(413)},
    {Node::kB3, Kind::kRequest, "options", "RFC 9110 9.3.7: OPTIONS answers 200 from options()",
     halt(200), to(Node::kC3)},

    {Node::kC3, Kind::kRequest, "content_types_provided",
     "RFC 9110 12.5.1: Accept absent takes the first provided type", to(Node::kC4), to(Node::kD4)},
    {Node::kC4, Kind::kConneg, "content_types_provided", "RFC 9110 12.5.1 / 15.5.7 (406)",
     to(Node::kD4), halt(406)},
    {Node::kD4, Kind::kRequest, "languages_provided",
     "RFC 9110 12.5.4: absent negotiates '*' and may still 406", to(Node::kD5), to(Node::kE5)},
    {Node::kD5, Kind::kConneg, "languages_provided", "RFC 9110 12.5.4 / 15.5.7 (406)",
     to(Node::kE5), halt(406)},
    {Node::kE5, Kind::kRequest, "charsets_provided",
     "RFC 9110 12.5.2: absent negotiates '*' and may still 406", to(Node::kE6), to(Node::kF6)},
    {Node::kE6, Kind::kConneg, "charsets_provided", "RFC 9110 12.5.2 / 15.5.7 (406)", to(Node::kF6),
     halt(406)},
    {Node::kF6, Kind::kRequest, "encodings_provided",
     "RFC 9110 12.5.3: absent negotiates identity;q=1,*;q=0.5; Content-Type header lands here",
     to(Node::kF7), to(Node::kG7)},
    {Node::kF7, Kind::kConneg, "encodings_provided", "RFC 9110 12.5.3 / 15.5.7 (406)",
     to(Node::kG7), halt(406)},

    {Node::kG7, Kind::kResource, "resource_exists?", "RFC 9110 12.5.5: Vary lands here",
     to(Node::kG8), to(Node::kH7)},
    {Node::kG8, Kind::kRequest, nullptr, "RFC 9110 13.1.1: If-Match present?", to(Node::kG9),
     to(Node::kH10)},
    {Node::kG9, Kind::kRequest, nullptr, "RFC 9110 13.1.1: If-Match is '*'?", to(Node::kH10),
     to(Node::kG11)},
    {Node::kG11, Kind::kResource, "generate_etag", "RFC 9110 13.1.1 / 15.5.13 (412)",
     to(Node::kH10), halt(412)},
    {Node::kH7, Kind::kRequest, nullptr,
     "RFC 9110 13.1.1: If-Match '*' against a missing resource is 412", halt(412), to(Node::kI7)},
    {Node::kH10, Kind::kRequest, nullptr, "RFC 9110 13.1.4: If-Unmodified-Since present?",
     to(Node::kH11), to(Node::kI12)},
    {Node::kH11, Kind::kRequest, nullptr, "RFC 9110 5.6.7: IUS parses as HTTP-date?",
     to(Node::kH12), to(Node::kI12)},
    {Node::kH12, Kind::kResource, "last_modified", "RFC 9110 13.1.4 / 15.5.13 (412)", halt(412),
     to(Node::kI12)},
    {Node::kI4, Kind::kResource, "moved_permanently?", "RFC 9110 15.4.2 (301) + Location",
     halt(301), to(Node::kP3)},
    {Node::kI7, Kind::kRequest, nullptr, "RFC 9110 9.3.4: PUT?", to(Node::kI4), to(Node::kK7)},
    {Node::kI12, Kind::kRequest, nullptr, "RFC 9110 13.1.2: If-None-Match present?", to(Node::kI13),
     to(Node::kL13)},
    {Node::kI13, Kind::kRequest, nullptr, "RFC 9110 13.1.2: If-None-Match is '*'?", to(Node::kJ18),
     to(Node::kK13)},
    {Node::kJ18, Kind::kRequest, nullptr,
     "RFC 9110 13.1.2: GET/HEAD gets 304 (15.4.5), others 412 (15.5.13)", halt(304), halt(412)},
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
    {Node::kL17, Kind::kResource, "last_modified", "RFC 9110 13.1.3 / 15.4.5 (304)", to(Node::kM16),
     halt(304)},

    {Node::kM5, Kind::kRequest, nullptr, "RFC 9110 15.5.11 (410): only POST may revive",
     to(Node::kN5), halt(410)},
    {Node::kM7, Kind::kResource, "allow_missing_post?", "RFC 9110 9.3.3 / 15.5.5 (404)",
     to(Node::kN11), halt(404)},
    {Node::kM16, Kind::kRequest, nullptr, "RFC 9110 9.3.5: DELETE?", to(Node::kM20),
     to(Node::kN16)},
    {Node::kM20, Kind::kAction, "delete_resource", "RFC 9110 9.3.5; false is 500 (15.6.1)",
     to(Node::kM20b), halt(500)},
    {Node::kM20b, Kind::kResource, "delete_completed?", "RFC 9110 15.3.3 (202) when async",
     to(Node::kO20), halt(202)},
    {Node::kN5, Kind::kResource, "allow_missing_post?", "RFC 9110 9.3.3 / 15.5.11 (410)",
     to(Node::kN11), halt(410)},
    {Node::kN11, Kind::kAction, "post_is_create?",
     "RFC 9110 9.3.3: create_path/base_uri or process_post; redirect is 303 (15.4.4)", halt(303),
     to(Node::kP11)},
    {Node::kN16, Kind::kRequest, nullptr, "RFC 9110 9.3.3: POST?", to(Node::kN11), to(Node::kO16)},
    {Node::kO14, Kind::kAction, "is_conflict?",
     "RFC 9110 15.5.10 (409); false runs content_types_accepted (accept_helper)", halt(409),
     to(Node::kP11)},
    {Node::kO16, Kind::kRequest, nullptr, "RFC 9110 9.3.4: PUT?", to(Node::kO14), to(Node::kO18)},
    {Node::kO18, Kind::kAction, "content_types_provided",
     "GET/HEAD render the body through the negotiated handler; caching headers land here",
     to(Node::kO18b), to(Node::kO18b)},
    {Node::kO18b, Kind::kResource, "multiple_choices?", "RFC 9110 15.4.1 (300) / 15.3.1 (200)",
     halt(300), halt(200)},
    {Node::kO20, Kind::kRequest, nullptr, "RFC 9110 15.3.5 (204): response carries no entity",
     to(Node::kO18), halt(204)},
    {Node::kP3, Kind::kAction, "is_conflict?",
     "RFC 9110 15.5.10 (409); false runs content_types_accepted (accept_helper)", halt(409),
     to(Node::kP11)},
    {Node::kP11, Kind::kRequest, nullptr, "RFC 9110 15.3.2 (201): Location was set", halt(201),
     to(Node::kO20)},
};

inline constexpr size_t kNodeCount = sizeof(kFlow) / sizeof(kFlow[0]);
static_assert(kNodeCount == static_cast<size_t>(Node::kCount), "one entry per node");

constexpr bool ids_in_order()
{
    for (size_t i = 0; i < kNodeCount; i++) {
        if (kFlow[i].id != static_cast<Node>(i))
            return false;
    }
    return true;
}
static_assert(ids_in_order(), "kFlow order must match Node order");

constexpr bool target_names_a_node_or_a_status(const Target &text)
{
    if (text.status == 0)
        return text.node < Node::kCount;
    return text.status >= 100 && text.status <= 599;
}
constexpr bool both_targets_of_every_node_name_one()
{
    for (size_t i = 0; i < kNodeCount; i++) {
        if (!target_names_a_node_or_a_status(kFlow[i].on_true) ||
            !target_names_a_node_or_a_status(kFlow[i].on_false)) {
            return false;
        }
    }
    return true;
}
static_assert(both_targets_of_every_node_name_one(), "every edge continues or halts");

// A walk of every path is exponential in the branches and crashed gcc 16's
// constexpr evaluator, so each node is entered once.
enum : uint8_t { kUnseen = 0, kOnThePath = 1, kFinished = 2 };
constexpr bool no_cycle_from(Node count, uint8_t (&colour)[kNodeCount])
{
    const size_t i = static_cast<size_t>(count);
    if (colour[i] == kOnThePath)
        return false;
    if (colour[i] == kFinished)
        return true;
    colour[i] = kOnThePath;
    const FlowNode &f = kFlow[i];
    if (f.on_true.status == 0 && !no_cycle_from(f.on_true.node, colour))
        return false;
    if (f.on_false.status == 0 && !no_cycle_from(f.on_false.node, colour))
        return false;
    colour[i] = kFinished;
    return true;
}
constexpr bool the_flow_is_acyclic()
{
    uint8_t colour[kNodeCount] = {};
    return no_cycle_from(Node::kB13, colour);
}
static_assert(the_flow_is_acyclic(), "the flow is acyclic from B13");

constexpr void mark(Node count, bool (&seen)[kNodeCount])
{
    const size_t i = static_cast<size_t>(count);
    if (seen[i])
        return;
    seen[i] = true;
    const FlowNode &f = kFlow[i];
    if (f.on_true.status == 0)
        mark(f.on_true.node, seen);
    if (f.on_false.status == 0)
        mark(f.on_false.node, seen);
}
constexpr bool all_reachable()
{
    bool seen[kNodeCount] = {};
    mark(Node::kB13, seen);
    for (bool s : seen) {
        if (!s)
            return false;
    }
    return true;
}
static_assert(all_reachable(), "every node is reachable from B13");

} // namespace webmachine::flow

namespace webmachine::flow
{
enum class Method : uint8_t { kGet, kHead, kPost, kPut, kDelete, kOptions, kOther };

//   has_accept*                 RFC 9110 12.5.1-12.5.4
//   has_if_match, *_star        RFC 9110 13.1.1
//   has_if_unmodified_since     RFC 9110 13.1.4
//   has_if_none_match, *_star   RFC 9110 13.1.2
//   has_if_modified_since       RFC 9110 13.1.3
//   *_valid                     RFC 9110 5.6.7: it parsed as an HTTP-date
//   response_has_*              RFC 9110 10.2.2 / 6.4
//   plain, no_track             no RFC: DNT and Sec-GPC
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
    // True by default: a request without Accept negotiates nothing (RFC 9110 12.5.1).
    bool accept_ok = true;
    bool response_has_location = false;
    bool response_has_body = true;
    bool plain = true;
    bool no_track = false;

    constexpr bool names_a_conneg_field() const
    {
        return has_accept || has_accept_language || has_accept_charset || has_accept_encoding;
    }
    constexpr bool names_a_conditional_field() const
    {
        return has_if_match || has_if_unmodified_since || has_if_none_match ||
               has_if_modified_since;
    }
};

struct KonstAnswers {
    bool ans[kNodeCount] = {};
};

constexpr bool eval_request(Node stream_id, const ReqFacts &round)
{
    switch (stream_id) {
        case Node::kB3:
            return round.method == Method::kOptions;
        case Node::kC3:
            return round.has_accept;
        case Node::kC4:
            return round.accept_ok;
        case Node::kD4:
            return round.has_accept_language;
        case Node::kE5:
            return round.has_accept_charset;
        case Node::kF6:
            return round.has_accept_encoding;
        case Node::kG8:
            return round.has_if_match;
        case Node::kG9:
            return round.if_match_star;
        case Node::kH7:
            return round.has_if_match && round.if_match_star;
        case Node::kH10:
            return round.has_if_unmodified_since;
        case Node::kH11:
            return round.if_unmodified_since_valid;
        case Node::kI7:
            return round.method == Method::kPut;
        case Node::kI12:
            return round.has_if_none_match;
        case Node::kI13:
            return round.if_none_match_star;
        case Node::kJ18:
            return round.method == Method::kGet || round.method == Method::kHead;
        case Node::kL7:
            return round.method == Method::kPost;
        case Node::kL13:
            return round.has_if_modified_since;
        case Node::kL14:
            return round.if_modified_since_valid;
        case Node::kL15:
            return round.if_modified_since_future;
        case Node::kM5:
            return round.method == Method::kPost;
        case Node::kM16:
            return round.method == Method::kDelete;
        case Node::kN16:
            return round.method == Method::kPost;
        case Node::kO16:
            return round.method == Method::kPut;
        case Node::kO20:
            return round.response_has_body;
        case Node::kP11:
            return round.response_has_location;
        default:
            return false;
    }
}

// RFC 9110 12.5: c4/d5/e6/f7 each hang off their own has_* node, so a
// request that names none of the four fields exits at g7.
inline constexpr Node kAfterConneg = Node::kG7;
// RFC 9110 13: g9/g11, h11/h12, i13/k13/j18 and l14/l15/l17 each hang off
// their own has_* node, so a request that names none of the four exits at m16.
inline constexpr Node kAfterConditional = Node::kM16;

constexpr uint16_t walk(const ReqFacts &request, const KonstAnswers &k)
{
    Node n = Node::kB13;
    for (;;) {
        if (n == Node::kC3 && !request.names_a_conneg_field())
            n = kAfterConneg;
        else if (n == Node::kG8 && !request.names_a_conditional_field())
            n = kAfterConditional;
        const FlowNode &field = kFlow[static_cast<size_t>(n)];
        // c4 compares the client's Accept against this resource's types, so no fold
        // can bake it. d5/e6/f7 stay konst: languages and charsets never move in this tree.
        const bool ans = (field.kind == Kind::kRequest || n == Node::kC4)
                             ? eval_request(n, request)
                             : k.ans[static_cast<size_t>(n)];
        const Target &text = ans ? field.on_true : field.on_false;
        if (text.status != 0)
            return text.status;
        n = text.node;
    }
}

struct Shortcut {
    uint16_t status = 0;
    bool always = false;
};

struct Walk {
    const KonstAnswers &answers;
    bool *seen;
};

constexpr bool reaches_a_node_that_reads_the_request(Node count, Walk window)
{
    const KonstAnswers &k = window.answers;
    bool *const seen = window.seen;
    if (seen[static_cast<size_t>(count)])
        return false;
    seen[static_cast<size_t>(count)] = true;
    const FlowNode &field = kFlow[static_cast<size_t>(count)];
    if (field.kind == Kind::kRequest || count == Node::kC4)
        return true;
    const Target &text = k.ans[static_cast<size_t>(count)] ? field.on_true : field.on_false;
    if (text.status != 0)
        return false;
    return reaches_a_node_that_reads_the_request(text.node, window);
}

struct Given {
    const ReqFacts &req;
    const KonstAnswers &konst;
};

constexpr Node lands_on(Node from, Given group)
{
    const ReqFacts &req = group.req;
    const KonstAnswers &k = group.konst;
    Node count = from;
    for (size_t step = 0; step < kNodeCount; step++) {
        const FlowNode &field = kFlow[static_cast<size_t>(count)];
        const bool ans = (field.kind == Kind::kRequest || count == Node::kC4)
                             ? eval_request(count, req)
                             : k.ans[static_cast<size_t>(count)];
        const Target &text = ans ? field.on_true : field.on_false;
        if (text.status != 0)
            return Node::kB13;
        count = text.node;
        if (count == kAfterConneg || count == kAfterConditional)
            return count;
    }
    return Node::kB13;
}

// Neither chain reads konst, so both konst extremes must give the same exit.
constexpr bool block_skips_are_the_graphs(Method method)
{
    ReqFacts absent;
    absent.method = method;
    KonstAnswers all_false{};
    KonstAnswers all_true{};
    for (size_t i = 0; i < kNodeCount; i++)
        all_true.ans[i] = true;
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

constexpr Shortcut shortcut_for(Method method, const KonstAnswers &k)
{
    Shortcut s;
    ReqFacts plain_facts;
    plain_facts.method = method;
    s.status = walk(plain_facts, k);
    bool seen[kNodeCount] = {};
    s.always = !reaches_a_node_that_reads_the_request(Node::kB13, {k, seen});
    return s;
}

struct Decided {
    const KonstAnswers &konst;
    const Shortcut &shortcut;
};

constexpr uint16_t answer(const ReqFacts &request, Decided dynamic_body)
{
    if (dynamic_body.shortcut.always || (request.plain && !request.has_accept))
        return dynamic_body.shortcut.status;
    return walk(request, dynamic_body.konst);
}

namespace detail
{
template <KonstAnswers K, Node N> constexpr uint16_t status_reached_from(const ReqFacts &request)
{
    constexpr FlowNode field = kFlow[static_cast<size_t>(N)];
    if constexpr (field.kind != Kind::kRequest) {
        constexpr Target text = K.ans[static_cast<size_t>(N)] ? field.on_true : field.on_false;
        if constexpr (text.status != 0)
            return text.status;
        else
            return status_reached_from<K, text.node>(request);
    } else {
        if (eval_request(N, request)) {
            if constexpr (field.on_true.status != 0)
                return field.on_true.status;
            else
                return status_reached_from<K, field.on_true.node>(request);
        } else {
            if constexpr (field.on_false.status != 0)
                return field.on_false.status;
            else
                return status_reached_from<K, field.on_false.node>(request);
        }
    }
}
} // namespace detail

template <KonstAnswers K> constexpr uint16_t walk_compiled(const ReqFacts &request)
{
    return detail::status_reached_from<K, Node::kB13>(request);
}

constexpr KonstAnswers answers_of_an_unoverridden_resource(Method method)
{
    KonstAnswers k{};
    k.ans[static_cast<size_t>(Node::kB13)] = true;
    k.ans[static_cast<size_t>(Node::kB12)] = method != Method::kOther;
    k.ans[static_cast<size_t>(Node::kB11)] = false;
    k.ans[static_cast<size_t>(Node::kB10)] = method == Method::kGet || method == Method::kHead;
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
    KonstSet()
    {
        for (uint8_t m = 0; m < 7; m++)
            per_method[m] = answers_of_an_unoverridden_resource(static_cast<Method>(m));
        resolve_shortcuts();
    }
    // Whoever changes per_method must call this.
    void resolve_shortcuts()
    {
        for (uint8_t m = 0; m < 7; m++) {
            shortcut[m] = shortcut_for(static_cast<Method>(m), per_method[m]);
        }
    }
};

namespace proof
{
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
static_assert(walk(get_plain, missing) == 404, "GET on a never-existed resource is 404 (L7)");
static_assert(walk_compiled<answers_of_an_unoverridden_resource(Method::kGet)>(get_plain) == 200);
static_assert(walk_compiled<answers_of_an_unoverridden_resource(Method::kDelete)>(del) == 405);
static_assert(
    walk_compiled<answers_of_an_unoverridden_resource(Method::kGet)>(if_none_match_star) == 304);
static_assert(walk_compiled<missing>(im_star_missing) == 412);
static_assert(walk_compiled<missing>(get_plain) == 404);
} // namespace proof
} // namespace webmachine::flow

#define E_WM_ERROR(mrb)                                                                            \
    (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Error)))
#define E_WM_CONFIG_ERROR(mrb)                                                                     \
    (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(ConfigError)))
#define E_WM_ROUTE_ERROR(mrb)                                                                      \
    (mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(RouteError)))

namespace webmachine
{

[[noreturn]] inline void reraise(mrb_state *mrb, mrb_value pending)
{
    if (mrb_exception_p(pending))
        mrb_exc_raise(mrb, pending);
    mrb_raisef(mrb, E_WM_ERROR(mrb), "a protected call ended with %v and no exception", pending);
    WM_UNREACHABLE();
}

[[noreturn]] inline void raise_errno(mrb_state *mrb, const char *what, int code)
{
    mrb_raisef(mrb, E_WM_ERROR(mrb), "%s: %s", what, std::strerror(code));
    WM_UNREACHABLE();
}

[[noreturn]] inline void raise_errno(mrb_state *mrb, const char *what, const char *which, int code)
{
    mrb_raisef(mrb, E_WM_ERROR(mrb), "%s %s: %s", what, which, std::strerror(code));
    WM_UNREACHABLE();
}

[[noreturn]] inline void throw_errno(const char *what, int code)
{
    throw std::system_error(code, std::system_category(), what);
}

// EINTR on Linux means the descriptor is already gone, so the call is never repeated.
inline void close_or_raise(mrb_state *mrb, const char *what, int fd)
{
    if (::close(fd) != 0 && errno != EINTR)
        raise_errno(mrb, "close", what, errno);
}

// A throw in a destructor ends the process through std::terminate with
// nothing said, so this says what failed first.
[[noreturn]] inline void die_errno(const char *what, int code)
{
    std::fprintf(stderr, "webmachine: %s: %s\n", what, std::strerror(code));
    std::abort();
}

inline void close_or_die(const char *what, int fd)
{
    if (::close(fd) != 0 && errno != EINTR)
        die_errno(what, errno);
}

inline void close_or_throw(const char *what, int fd)
{
    if (::close(fd) != 0 && errno != EINTR)
        throw_errno(what, errno);
}

// The entries are read through mrb_ary_entry and never through a pointer
// into the Array's storage, so the block may grow that Array while it runs.
inline mrb_value yield_array_entries(mrb_state *mrb, mrb_value block, mrb_value array)
{
    const mrb_int count = mrb_array_p(array) ? RARRAY_LEN(array) : 0;
    std::vector<mrb_value> entries(static_cast<size_t>(count));
    for (mrb_int i = 0; i < count; i++)
        entries.at(static_cast<size_t>(i)) = mrb_ary_entry(array, i);
    return mrb_yield_argv(mrb, block, count, entries.data());
}

[[noreturn]] inline void rethrow(mrb_state *mrb)
{
    const mrb_value exc = mrb_obj_value(mrb->exc);
    mrb->exc = nullptr;
    reraise(mrb, exc);
}

struct io_uring_sqe *sqe_or_raise(mrb_state *mrb, struct io_uring *ring);

// mrb_open runs every gem init. A gem init that raises leaves its
// exception in mrb->exc with the VM otherwise standing.
mrb_state *open_vm_or_say(const char *who);

class ArenaGuard
{
  public:
    explicit ArenaGuard(mrb_state *mrb) : mrb_(mrb), at_(mrb_gc_arena_save(mrb))
    {
    }
    ~ArenaGuard()
    {
        mrb_gc_arena_restore(mrb_, at_);
    }
    ArenaGuard(const ArenaGuard &) = delete;
    ArenaGuard &operator=(const ArenaGuard &) = delete;

  private:
    mrb_state *const mrb_;
    const int at_;
};

// mruby's own number: mrb_funcall holds its arguments in an array of
// this size and raises above it.
#ifdef MRB_FUNCALL_ARGC_MAX
inline constexpr size_t kMaxRouteBindings = MRB_FUNCALL_ARGC_MAX;
#else
inline constexpr size_t kMaxRouteBindings = 16;
#endif

struct RouteSpans {
    struct Span {
        const char *p;
        size_t n;
    };
    Span bind[kMaxRouteBindings];
    Span splat;
    uint8_t nbind;
    bool has_splat;
};

class RouteTable
{
  public:
    enum Kind : uint8_t { kLiteral, kBinding, kSplat };

    void open()
    {
        pending_first_ = toks_.size();
        pending_blob_ = blob_.size();
        pending_binds_ = 0;
        pending_splat_ = false;
    }
    bool literal(const char *bytes, size_t count)
    {
        if (count > 0xffffu)
            return false;
        RouteToken t;
        t.kind = kLiteral;
        t.off = static_cast<uint32_t>(blob_.size());
        t.len = static_cast<uint32_t>(count);
        blob_.append(bytes, count);
        toks_.push_back(t);
        return true;
    }
    bool binding(uint32_t sym)
    {
        if (pending_binds_ >= kMaxRouteBindings)
            return false;
        pending_binds_++;
        toks_.push_back(RouteToken{kBinding, sym, 0});
        return true;
    }

    uint32_t binding_sym(int route, uint8_t i) const
    {
        const Route &retry = routes_[static_cast<size_t>(route)];
        uint8_t seen = 0;
        for (uint32_t t = 0; t < retry.count; t++) {
            const RouteToken &token = toks_[retry.first + t];
            if (token.kind != kBinding)
                continue;
            if (seen == i)
                return token.off;
            seen++;
        }
        return 0;
    }
    void splat()
    {
        pending_splat_ = true;
        toks_.push_back(RouteToken{kSplat, 0, 0});
    }
    bool pending_splat() const
    {
        return pending_splat_;
    }
    void commit()
    {
        Route r;
        r.first = static_cast<uint32_t>(pending_first_);
        r.count = static_cast<uint32_t>(toks_.size() - pending_first_);
        routes_.push_back(r);
    }
    void abandon()
    {
        toks_.resize(pending_first_);
        blob_.resize(pending_blob_);
    }

    size_t size() const
    {
        return routes_.size();
    }
    bool empty() const
    {
        return routes_.empty();
    }

    int match(const char *path, size_t length, RouteSpans &out_value) const
    {
        // The spans are written only as far as nbind and has_splat admit, so
        // RouteSpans may stay uninitialized at the top of a request path.
        out_value.nbind = 0;
        out_value.has_splat = false;
        size_t plen = length;
        for (size_t i = 0; i < length; i++) {
            if (path[i] == '?') {
                plen = i;
                break;
            }
        }
        size_t start = 0;
        if (start < plen && path[start] == '/')
            start++;
        const char *blob = blob_.data();
        const size_t count = routes_.size();
        for (size_t r = 0; r < count; r++) {
            const Route &retry = routes_[r];
            size_t bytes = start;
            uint8_t name_bytes = 0;
            bool accepted = true;
            bool splat = false;
            for (uint32_t text = 0; text < retry.count; text++) {
                const RouteToken &token = toks_[retry.first + text];
                if (token.kind == kSplat) {
                    out_value.splat.p = path + bytes;
                    out_value.splat.n = plen - bytes;
                    bytes = plen;
                    splat = true;
                    break;
                }
                if (bytes >= plen) {
                    accepted = false;
                    break;
                }
                const size_t seg = bytes;
                while (bytes < plen && path[bytes] != '/')
                    bytes++;
                const size_t seglen = bytes - seg;
                if (token.kind == kLiteral) {
                    if (seglen != token.len ||
                        std::memcmp(path + seg, blob + token.off, seglen) != 0) {
                        accepted = false;
                        break;
                    }
                } else {
                    out_value.bind[name_bytes].p = path + seg;
                    out_value.bind[name_bytes].n = seglen;
                    name_bytes++;
                }
                if (bytes < plen)
                    bytes++;
            }
            if (!accepted)
                continue;
            if (!splat && bytes < plen)
                continue;
            out_value.nbind = name_bytes;
            out_value.has_splat = splat;
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

class OpenRoute
{
  public:
    explicit OpenRoute(RouteTable &table) : table_(table)
    {
        table_.open();
    }
    ~OpenRoute()
    {
        if (!stands_)
            table_.abandon();
    }
    OpenRoute(const OpenRoute &) = delete;
    OpenRoute &operator=(const OpenRoute &) = delete;
    void commit()
    {
        table_.commit();
        stands_ = true;
    }

  private:
    RouteTable &table_;
    bool stands_ = false;
};
} // namespace webmachine

namespace webmachine
{
// The access log is the NCSA Combined Log Format. No specification
// exists for it, so no line here can be checked against a source.
struct Logger {
    bool enabled = false;
    std::string pending;
    std::string flight; // the kernel owns these bytes while in flight
    bool in_flight = false;
    int64_t unix_seconds = 0;
    size_t dropped = 0;
};
// Four megabytes is thousands of records: minutes of a slow daemon, not one that is gone.
inline constexpr size_t kLogQueueCap = 4u * 1024 * 1024;

bool log_queue_full(Logger &logger);

//   status_code      RFC 9110 15
//   content_length   RFC 9110 8.6 - octets of content, headers excluded
//   method_token     RFC 9110 9.1
//   request_target   RFC 9112 3.2
//   referer          RFC 9110 10.1.3 - the RFC misspells it, so do we
//   user_agent       RFC 9110 10.1.5
// The *_len widths are the truncation caps, so log_access clamps to them.
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

// The format is ours because argon2's own encoded form cannot carry the
// ad parameter. ad is the sub-database's name and is not stored: both
// sides hold it, so a row copied to another sub-database is unverifiable.
// Native widths and native order: LMDB already refuses a file written by
// another endianness or word size.
struct PasswdRec {
    uint8_t version;
    uint8_t salt_len;
    uint8_t hash_len;
    uint8_t lanes; // argon2's p
    uint32_t m_kib; // argon2's m, in KiB
    uint32_t t; // argon2's t
    int64_t ctime;
    int64_t mtime;
    // salt_len bytes of salt follow, then hash_len bytes of hash.
};
inline constexpr uint8_t kPasswdRecVersion = 1;

inline constexpr uint8_t kLogH2 = 1; // RFC 9113
inline constexpr uint8_t kLogNoTrack = 2;

struct AccessLine {
    std::string_view peer;
    std::string_view method_token; // RFC 9110 9.1
    std::string_view request_target; // RFC 9112 3.2
    std::string_view referer; // RFC 9110 10.1.3 - the RFC misspells it
    std::string_view user_agent; // RFC 9110 10.1.5
    size_t content_length = 0; // RFC 9110 8.6 - content octets, no headers
    uint16_t status_code = 0; // RFC 9110 15
    uint8_t flags = 0;
};

void log_access(Logger &logger, const AccessLine &line);

//   status_code      RFC 9110 15, or 0 when the raise never reached an answer
//   request_target   RFC 9112 3.2
//   dynamic_len      the length of the second io_uring_prep_send: the daemon
//                    reads this fixed header, then takes that many bytes
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
    // body_full_len is the real length, so a truncated body is not passed off as whole.
    uint16_t body_len;
    uint32_t body_full_len;
    // The same 16 bytes the page spells, so the hash a user reads off a page
    // finds this record. app_build tells a hash from before a deploy apart
    // from one from the running code.
    char fingerprint[16];
    char app_build[16];
    uint32_t dynamic_len;
};
inline constexpr uint8_t kErrRecVersion = 2;
inline constexpr size_t kFingerprintLen = 16;
// The body may hold a password, so an error log is a file with secrets in it.
inline constexpr size_t kBodyKept = 4096;

// A lend costs a segment: sendmsg with an iovec instead of send with one
// pointer. Two h1 profiles measured it at five points of one core (before:
// io_send 2.26%; after: io_msg_copy_hdr 1.68, ____sys_sendmsg 1.42,
// copy_iovec_from_user 1.39, __import_iovec 0.81). A 39-byte body saves
// nothing by a lend. 300 stalled readers of a 64 KB answer held 19.5 MB
// of duplicates. bench/floor.sh moves this number.
inline constexpr size_t kLendFloor = 4096;

// FNV-1a over the bytecode the server loaded, taken once at startup.
// Every fingerprint carries it, so a hash from before a deploy cannot
// point at a line that has moved.
uint64_t &app_build_hash();

// FNV-1a, 64 bit: offset basis and prime from the reference implementation.
inline constexpr uint64_t kFnvBasis = 0xcbf29ce484222325ULL;
uint64_t fnv1a(uint64_t headers, const void *bytes, size_t count);
// A length in front of every piece, so "/a" + "bc" and "/ab" + "c" are
// two fingerprints and not one.
uint64_t fnv1a_piece(uint64_t headers, const void *bytes, size_t count);
void spell_fingerprint(char *out_value, uint64_t headers);

// The fingerprint is taken over this and nothing else, so a record and a page cannot disagree.
struct ErrFacts {
    const void *peer = nullptr;
    size_t peer_len = 0;
    const char *request_target = nullptr;
    size_t request_target_len = 0;
    const char *method = nullptr;
    size_t method_len = 0;
    const char *steering = nullptr;
    size_t steering_len = 0;
    const char *exception_class = nullptr;
    size_t exception_class_len = 0;
    const char *message = nullptr;
    size_t message_len = 0;
    const char *backtrace = nullptr;
    size_t backtrace_len = 0;
    const char *body = nullptr;
    size_t body_len = 0;
    size_t body_full = 0;
    uint16_t status_code = 0;
};

// The message is not in the hash: the same fault at the same place under
// the same request is one failure, whatever the exception said.
uint64_t fingerprint_of(const ErrFacts &field);

// A fixed header whose last field is the size of the second send, then
// that many bytes: peer, class, target, message, backtrace, method, steering.
void log_error(Logger &logger, const ErrFacts &field);

struct ErrorLine {
    std::string_view peer;
    std::string_view request_target; // RFC 9112 3.2
    std::string_view why;
    uint16_t status_code = 0; // RFC 9110 15
};

void log_internal_error(Logger &logger, const ErrorLine &line);

// An mrb_value belongs to the VM that made it, so the worker spells the exception as text.
struct ComputeFault {
    std::string_view exception; // CBOR
    std::string_view step;
    std::string_view worker_name;
    std::string_view peer;
    uint16_t status;
};

void say_server_error(Logger *logger, std::string_view why);

// mruby's enable_debug defines MRB_DEBUG and the ship configs do not.
#ifdef MRB_DEBUG
inline constexpr bool kDebugBuild = true;
#else
inline constexpr bool kDebugBuild = false;
#endif

// The caller owns `backtrace`, and the facts point into it.
struct Raised {
    ErrFacts &facts;
    std::string &backtrace;
};
void exception_facts(mrb_state *mrb, Raised out_value);

// No request: a stream answered long ago now runs app code of its own.
// There is no target and no method, so the fingerprint is the build, the
// class and the place.
void log_raise(Logger &logger, mrb_state *mrb, uint16_t status);

void report_raise(Logger *logger, mrb_state *mrb, uint16_t status);
void fault_report(Logger *logger, mrb_state *mrb, const ComputeFault &one);
} // namespace webmachine

namespace webmachine::http
{
// RFC 9110 5.1: case-insensitive equality against a lowercase literal.
constexpr bool tok_eq(std::string_view text, std::string_view lit)
{
    const char *const text_bytes = text.data();
    const size_t count = text.size();
    if (count != lit.size())
        return false;
    for (size_t i = 0; i < count; i++) {
        char letter = text_bytes[i];
        if (letter >= 'A' && letter <= 'Z')
            letter = static_cast<char>(letter + 32);
        if (letter != lit[i])
            return false;
    }
    return true;
}

// RFC 9110 13.1.1 / 13.1.2: If-Match and If-None-Match spell "any" as *.
constexpr bool star_value(const char *value, size_t count)
{
    if (count == 1 && value[0] == '*')
        return true;
    return count == 3 && value[0] == '"' && value[1] == '*' && value[2] == '"';
}

// RFC 9110 4.2.1: the query is not part of the path.
size_t path_only(const char *bytes, size_t count);

// RFC 9110 9.1: methods are case-sensitive tokens.
inline flow::Method parse_method(const char *method, size_t count)
{
    switch (count) {
        case 3:
            if (std::memcmp(method, "GET", 3) == 0)
                return flow::Method::kGet;
            if (std::memcmp(method, "PUT", 3) == 0)
                return flow::Method::kPut;
            break;
        case 4:
            if (std::memcmp(method, "HEAD", 4) == 0)
                return flow::Method::kHead;
            if (std::memcmp(method, "POST", 4) == 0)
                return flow::Method::kPost;
            break;
        case 6:
            if (std::memcmp(method, "DELETE", 6) == 0)
                return flow::Method::kDelete;
            break;
        case 7:
            if (std::memcmp(method, "OPTIONS", 7) == 0)
                return flow::Method::kOptions;
            break;
        default:
            break;
    }
    return flow::Method::kOther;
}

// RFC 9110 8.3: text/* without parameters gets charset=utf-8.
std::string with_charset(const std::string &type);

constexpr size_t clen(const char *sqe)
{
    size_t n = 0;
    while (sqe[n] != '\0')
        n++;
    return n;
}
// RFC 6839: +json and +xml are structured-syntax suffixes.
constexpr bool compressible_media_type(const char *value, size_t count)
{
    size_t tn = 0;
    while (tn < count && value[tn] != ';')
        tn++;
    if (tn >= 5 && tok_eq({value, 5}, "text/"))
        return true;
    if (tn >= 5 && tok_eq({value + tn - 5, 5}, "+json"))
        return true;
    if (tn >= 4 && tok_eq({value + tn - 4, 4}, "+xml"))
        return true;
    constexpr const char *kExact[] = {
        "application/json", "application/javascript", "application/xml",
        "application/wasm", "image/svg+xml",
    };
    for (const char *lit : kExact) {
        if (tok_eq({value, tn}, lit))
            return true;
    }
    return false;
}
bool compressible_media_type(const std::string &value);
namespace proof
{
constexpr bool ct(const char *sqe)
{
    return compressible_media_type(sqe, clen(sqe));
}
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
} // namespace proof

// RFC 9110 15.
constexpr const char *reason(uint16_t status)
{
    switch (status) {
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 204:
            return "No Content";
        case 206:
            return "Partial Content";
        case 300:
            return "Multiple Choices";
        case 301:
            return "Moved Permanently";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 307:
            return "Temporary Redirect";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 411:
            return "Length Required";
        case 412:
            return "Precondition Failed";
        case 413:
            return "Content Too Large";
        case 414:
            return "URI Too Long";
        case 415:
            return "Unsupported Media Type";
        case 416:
            return "Range Not Satisfiable";
        case 431:
            return "Request Header Fields Too Large";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 503:
            return "Service Unavailable";
    }
    return "Response";
}

inline constexpr char kDatePlaceholder[] = "Sun, 00 Jan 1970 00:00:00 GMT";
inline constexpr size_t kDateLen = sizeof(kDatePlaceholder) - 1;

void write_two_digits(char *out_value, int value);

// RFC 9110 5.6.7: IMF-fixdate by hand, because strftime obeys the locale.
void date_core(char out_value[kDateLen], const struct tm &broken_time);

size_t spell_content_length(char (&buf)[40], size_t length);

// RFC 9112 7.1: one hexadecimal digit of a chunk size.
int hex_digit(char character);

enum class ClStatus : uint8_t { kOk, kBad, kOverflow };
// RFC 9110 8.6: 1*DIGIT. kBad is the caller's 400, kOverflow its 413.
ClStatus parse_content_length(std::string_view value, size_t *out_value);

// One pass over the field array notes where each of these sits. A later
// ask is a bit test and an index, never a second walk.
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

struct HeaderList {
    const struct phr_header *items;
    size_t count;
};

struct NamedFieldIndex {
    // A stored position means something only for the array it was taken
    // from, so `find` takes that array back in and answers nullptr for
    // anything it cannot reach.
    const struct phr_header *find(NamedField field, HeaderList fields) const;

    constexpr void note(NamedField field, size_t i)
    {
        if (i > 255)
            return;
        const auto block = static_cast<uint8_t>(field);
        // RFC 9110 5.2: a repeated field is one list, and the first occurrence starts it.
        if (((present >> block) & 1u) != 0)
            return;
        present = static_cast<uint16_t>(present | (1u << block));
        index[block] = static_cast<uint8_t>(i);
    }
    constexpr bool carries(NamedField field) const
    {
        return ((present >> static_cast<uint8_t>(field)) & 1u) != 0;
    }

  private:
    uint16_t present = 0;
    uint8_t index[static_cast<size_t>(NamedField::kCount)] = {};
};
struct ReqValues {
    const char *log_ref = nullptr;
    size_t log_ref_len = 0;
    const char *log_ua = nullptr;
    size_t log_ua_len = 0;

    const char *accept_encoding = nullptr;
    size_t accept_encoding_len = 0;
    const char *if_match = nullptr;
    size_t if_match_len = 0;
    const char *if_none_match = nullptr;
    size_t if_none_match_len = 0;
    const char *range = nullptr;
    size_t range_len = 0;
    const char *if_range = nullptr;
    size_t if_range_len = 0;

    // b8 gets Authorization (RFC 9110 11.6.2), b5 gets Content-Type (8.3).
    const char *authorization = nullptr;
    size_t authorization_len = 0;
    const char *content_type = nullptr;
    size_t content_type_len = 0;
    // c4 negotiates against Accept (RFC 9110 12.5.1). request.base_uri and
    // request.cookies read Host (7.2) and Cookie (RFC 6265).
    const char *accept = nullptr;
    size_t accept_len = 0;
    const char *host = nullptr;
    size_t host_len = 0;
    const char *cookie = nullptr;
    size_t cookie_len = 0;
    // RFC 9110 5.6.7. Valid only when the matching *_valid fact is set.
    int64_t if_unmodified_since_epoch = 0;
    int64_t if_modified_since_epoch = 0;
    NamedFieldIndex named;
    // RFC 9110 5.3: the field came more than once, and the span above is the
    // first line's. RFC 9113 8.2.3 lets an h2 client split Cookie.
    bool cookie_repeats = false;
    bool if_none_match_repeats = false;
};

// A parked run rebases every pointer in ReqValues, and one missed is a
// dangling pointer. The size assert stops the build when a field is added
// and not listed here.
inline constexpr const char *ReqValues::*kReqValueSpans[] = {
    &ReqValues::log_ref,  &ReqValues::log_ua,        &ReqValues::accept_encoding,
    &ReqValues::if_match, &ReqValues::if_none_match, &ReqValues::range,
    &ReqValues::if_range, &ReqValues::authorization, &ReqValues::content_type,
    &ReqValues::accept,   &ReqValues::host,          &ReqValues::cookie,
};
static_assert(sizeof(ReqValues) == 224,
              "ReqValues changed shape: a new field belongs in kReqValueSpans, and a "
              "removed one has to leave it - see #80, the parked run's rebase");

// std::less orders two pointers into different objects, where `<` is
// undefined.
bool follow_copy(std::string_view was, std::string_view now, const char *&bytes);

void rebase(ReqValues &value, std::string_view was, std::string_view now);

// Referer and User-Agent steer nothing, so they stay out of the fingerprint.
// Authorization is named by its scheme and never by what follows it (RFC
// 9110 11.6.2): the credential belongs in no file. Cookie is named without
// its value for the same reason.
void spell_steering(const ReqValues *value, std::string &out_value);

bool read_size(const char *value, size_t count, size_t &i, size_t *out_value);

enum class RangeParse : uint8_t { kNone, kOne, kUnsat };
// RFC 9110 14.1.2. kNone means act as if the field were absent, which 14.2 permits.
struct RangeField {
    std::string_view value;
    size_t complete;
};

struct ByteRange {
    size_t first;
    size_t last;
};

RangeParse parse_range(RangeField field, ByteRange &out_value);

// RFC 9110 14.2: one validator, compared strongly. A date reads as no match.
bool if_range_matches(std::string_view value, std::string_view poll_tag);

// RFC 9110 12.5.3: the most specific match wins.
bool gzip_acceptable(const char *value, size_t count);

// RFC 9111 4.2.2: a cache may guess freshness from a validator. The target
// "/" keeps its name while the page behind it changes, so a guessed index
// page never updates. "/app.7f3c.js" is a new name for new bytes.
bool target_names_a_directory(std::string_view target);

// RFC 9111 5.2.2.4: no-cache keeps the copy and revalidates it before every reuse.
inline constexpr char kNoCacheLine[] = "Cache-Control: no-cache\r\n";

// Cache-Control wins over Expires where both are present (RFC 9111 4.2.1).
bool freshness_is_stated(std::string_view field_lines);

// RFC 9110 13.1.1 / 13.1.2: strong for If-Match, weak for If-None-Match.
struct EtagMatch {
    std::string_view list;
    std::string_view tag;
    bool weak;
};

bool etag_list_match(EtagMatch method);

int read_fixed_digits(const char *bytes, size_t index, size_t k);

int read_month_name(const char *bytes, size_t index);

// days_from_civil (Howard Hinnant): proleptic Gregorian, no libc.
struct Civil {
    int y;
    int m;
    int d;
    int hh;
    int mm;
    int ss;
};

int64_t epoch_from_civil(Civil conn);

// RFC 9110 5.6.7: IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT"), obsolete
// RFC 850 ("Sunday, 06-Nov-94 08:49:37 GMT") and asctime
// ("Sun Nov  6 08:49:37 1994").
bool parse_http_date(const char *bytes, size_t count, int64_t *out_value);

// RFC 9110 12.5.1: most specific match per type, highest q wins, the
// provided order breaks ties. Matching reads only the type/subtype half.
struct Conneg {
    std::span<const std::string> provided;
    std::string_view accept;
};

// RFC 9110 12.5.1: an exact type/subtype is the most specific match a
// range can be, so a first range equal to the offered type settles the
// question. A parameter or a case difference falls back to choose_media_type.
bool accept_is_exact(std::string_view accept, std::string_view type);

int choose_media_type(Conneg conn);

// RFC 9110 8.8.3: a quoted or weak form passes verbatim, bare bytes are quoted.
void etag_spell(const char *raw, size_t count, std::string &out_value);

struct UriRef {
    std::string_view base;
    std::string_view ref;
};

// RFC 3986 5.3: a full URI passes verbatim, an absolute-path ref replaces
// the base's path, a relative segment appends after the base's last '/'.
void uri_join(UriRef round, std::string &out_value);

// RFC 9110 6.1: the server spells Content-Length and Connection itself, so
// a resource that writes one puts a second copy on the wire. Two
// Content-Length fields are a response desync. Over HTTP/2 the hop-by-hop
// names are refused (RFC 9113 8.2.2).
// RFC 9110 5.1 / 5.6.2: a field name is a token. Without the check, an app
// that answers generate_etag with "v1\r\nSet-Cookie: a=b" splices a field
// into the answer.
bool field_name_is_the_servers(const char *bytes, size_t count);

bool field_name_ok(const char *bytes, size_t count);

// Eight octets at a time. A word minus 0x01 in every octet, and-not the
// word, and 0x80 in every octet, is non-zero exactly when an octet was
// zero. XOR with a repeated octet turns "is CR" into the same zero test.
// With n in place of 0x01 it is non-zero exactly when an octet is under n.
inline constexpr uint64_t kOctet01Repeated = 0x0101010101010101ULL;
inline constexpr uint64_t kOctet80Repeated = 0x8080808080808080ULL;

constexpr uint64_t octet_repeated(unsigned char octet)
{
    return kOctet01Repeated * octet;
}

constexpr bool word_has_zero_octet(uint64_t word)
{
    return ((word - kOctet01Repeated) & ~word & kOctet80Repeated) != 0;
}

constexpr bool word_has_octet_under(uint64_t word, unsigned char bound)
{
    return ((word - octet_repeated(bound)) & ~word & kOctet80Repeated) != 0;
}

constexpr bool word_is_field_value(uint64_t word)
{
    return !word_has_zero_octet(word) && !word_has_zero_octet(word ^ octet_repeated('\r')) &&
           !word_has_zero_octet(word ^ octet_repeated('\n'));
}

// RFC 9110 5.5: a field value carries no CR, LF or NUL. Obs-fold is gone
// (RFC 9112 5.2) and RFC 9113 8.2.1 makes either byte malformed, so one
// rule serves both writers.
inline bool field_value_ok(const char *bytes, size_t count)
{
    std::string_view left(bytes, count);
    while (left.size() >= sizeof(uint64_t)) {
        uint64_t word;
        std::memcpy(&word, left.data(), sizeof word);
        if (!word_is_field_value(word))
            return false;
        left.remove_prefix(sizeof word);
    }
    for (const char octet : left) {
        if (octet == '\r' || octet == '\n' || octet == '\0')
            return false;
    }
    return true;
}

// The mask is derived from the list, so a new case cannot forget to widen it.
constexpr uint32_t lengths_mask(const size_t *value, size_t count)
{
    uint32_t m = 0;
    for (size_t i = 0; i < count; i++)
        m |= 1u << value[i];
    return m;
}
constexpr bool length_is_one_of(size_t nlen, uint32_t mask)
{
    return nlen < 32 && ((mask >> nlen) & 1u) != 0;
}

// dnt(3) host(4) range(5) accept/cookie(6) sec-gpc(7)
// if-match/if-range(8) content-type(12) authorization/if-none-match(13)
// accept-charset(14) accept-encoding/accept-language(15)
// if-modified-since(17) if-unmodified-since(19).
inline constexpr size_t kFieldLengths[] = {3, 4, 5, 6, 7, 8, 12, 13, 14, 15, 17, 19};
inline constexpr uint32_t kFieldLengthMask =
    lengths_mask(kFieldLengths, sizeof(kFieldLengths) / sizeof(kFieldLengths[0]));

struct Field {
    std::string_view name;
    std::string_view value;
};

struct FactSink {
    flow::ReqFacts &facts;
    ReqValues &vals;
    size_t at;
};

// True means the name is not one of the RFC 9110 facts and the framer must read it.
static inline bool header_switch(Field field, FactSink into)
{
    const char *const name = field.name.data();
    const size_t nlen = field.name.size();
    const char *const value = field.value.data();
    const size_t vlen = field.value.size();
    flow::ReqFacts &facts = into.facts;
    ReqValues &vals = into.vals;
    const size_t at = into.at;
    if (!length_is_one_of(nlen, kFieldLengthMask))
        return true;
    switch (nlen) {
        case 3:
            if (tok_eq({name, nlen}, "dnt")) {
                if (vlen == 1 && value[0] == '1')
                    facts.no_track = true;
                return false;
            }
            break;
        case 4:
            if (tok_eq({name, nlen}, "host")) {
                // RFC 9112 requires Host, so the presence check stays the framer's. This
                // arm keeps the bytes and falls through to the framer.
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
                // `plain` stays true: answer() asks has_accept separately, so the request
                // path can clear it when the Accept names exactly what the route offers.
                facts.has_accept = true;
                vals.accept = value;
                vals.accept_len = vlen;
                vals.named.note(NamedField::kAccept, at);
                return false;
            }
            if (tok_eq({name, nlen}, "cookie")) {
                if (vals.cookie != nullptr) {
                    vals.cookie_repeats = true;
                    return false;
                }
                vals.cookie = value;
                vals.cookie_len = vlen;
                return false;
            }
            break;
        case 7:
            if (tok_eq({name, nlen}, "sec-gpc")) {
                if (vlen == 1 && value[0] == '1')
                    facts.no_track = true;
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
                vals.content_type = value;
                vals.content_type_len = vlen;
                vals.named.note(NamedField::kContentType, at);
                return false;
            }
            break;
        case 13:
            if (tok_eq({name, nlen}, "authorization")) {
                vals.authorization = value;
                vals.authorization_len = vlen;
                vals.named.note(NamedField::kAuthorization, at);
                return false;
            }
            if (tok_eq({name, nlen}, "if-none-match")) {
                facts.has_if_none_match = true;
                facts.plain = false;
                if (vals.if_none_match != nullptr) {
                    if (star_value(value, vlen))
                        facts.if_none_match_star = true;
                    vals.if_none_match_repeats = true;
                    return false;
                }
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
                // RFC 9110 13.1.3: an unparseable date reads as field absent (l14).
                vals.named.note(NamedField::kIfModifiedSince, at);
                facts.if_modified_since_valid =
                    parse_http_date(value, vlen, &vals.if_modified_since_epoch);
                // RFC 9110 13.1.3: a date in the future is ignored (l15).
                if (facts.if_modified_since_valid) {
                    facts.if_modified_since_future = vals.if_modified_since_epoch > ::time(nullptr);
                }
                return false;
            }
            break;
        case 19:
            if (tok_eq({name, nlen}, "if-unmodified-since")) {
                facts.has_if_unmodified_since = true;
                facts.plain = false;
                // RFC 9110 13.1.4: the same rule as If-Modified-Since (h11).
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
} // namespace webmachine::http

namespace webmachine
{
// RFC 9110 3.4: every field is lent and valid for the frame that
// dispatches it. A run may read this. A run may not keep it.
struct ReqView {
    // RFC 9112 3.2 / RFC 9113 8.3.1. path_len is RFC 3986 3.3's path.
    const char *request_target = nullptr;
    size_t request_target_len = 0;
    size_t path_len = 0;
    flow::Method method = flow::Method::kGet;
    const char *method_token = nullptr;
    size_t method_token_len = 0;
    const RouteTable *table = nullptr;
    int route = -1;
    // Lent from the caller's frame. A copy costs 280 bytes.
    const RouteSpans *spans = nullptr;
    const void *fields = nullptr;
    size_t field_count = 0;
    const http::ReqValues *values = nullptr;
    bool tls = false;
    // RFC 9110 6.4. Lent for the frame: it dies with the dispatch.
    const char *content = nullptr;
    size_t content_len = 0;
    // A body of kBodySpill or more is in a file, and then `content` is null.
    // -1 says the body is where `content` points.
    int content_fd = -1;
    // False says the client declared content that has not all arrived.
    bool content_ready = true;
    // RFC 9110 8.6: the declared count, which is not content_len. content_len
    // is zero while the body is still coming. B4 asks about the declared
    // number at the head.
    size_t declared_len = 0;
};

void join_repeated_fields(const ReqView *value, std::string_view name, std::string_view sep,
                          std::string &out);

void request_init(mrb_state *mrb, struct RClass *webmachine_module);

void request_bind(const ReqView *view);

// Lives in request.cpp so that h2_dispatch stays header_switch's only
// caller in http2.cpp. A second caller there stops the switch from inlining.
void values_of_copied_fields(http::HeaderList headers, http::ReqValues &out_value);

void request_disp_override(const char *bytes, size_t count);
} // namespace webmachine

namespace webmachine
{
// Every cb_* is a callback of webmachine-ruby's Resource::Callbacks,
// spelled exactly as an app spells it. That is the contract, so no name
// here is abbreviated. Arguments of a NativeCb arrive as C++ arguments and
// never through mrb_get_args, so it never reads the callinfo and may be
// entered straight from C++.
using NativeCb = mrb_value (*)(mrb_state *mrb, mrb_value self, mrb_int argc, const mrb_value *argv);

struct Native {
    mrb_sym sym;
    NativeCb fn;
    mrb_aspec aspec = MRB_ARGS_ANY();
};
void define_native(mrb_state *mrb, struct RClass *conn, Native count);

struct AssetEntry;

// What fits in the tag's spare byte.
inline constexpr unsigned kMaxWatchers = 256;

// A node's own callback is one. A value round asks for an ETag, a
// Last-Modified, an Expires and a body, and none of them chooses an edge,
// so all four may run at the same time.
inline constexpr int kValueJobs = 4;
enum : uint8_t { kJobNode = 0, kJobEtag = 1, kJobLastModified = 2, kJobExpires = 3 };

struct Resource {

    flow::KonstSet konst;
    mrb_state *mrb = nullptr;
    struct RClass *klass = nullptr;
    // Entering a `def self.x` method directly needs the class it was found
    // in. The fold freezes klass, so this pointer is as stable as klass.
    struct RClass *meta_klass = nullptr;
    uint64_t dynamic = 0;
    // A subset of `dynamic`, read in the same load, so a run knows before it
    // enters the VM whether this node can stop.
    uint64_t compute = 0;
    // Nodes declared with `watch :name`. The block runs in this VM, so it
    // may keep its environment and live on the instance.
    uint64_t watch = 0;
    mrb_sym node_sym[flow::kNodeCount] = {};
    mrb_method_t node_m[flow::kNodeCount] = {};
    bool node_irep[flow::kNodeCount] = {};
    NativeCb node_native[flow::kNodeCount] = {};
    uint64_t node_on_class = 0;
    bool dynamic_body = false;
    bool gzip_offered = false;
    bool init_needed = false;
    // Object's initialize is undef'd on Webmachine::Resource, so init_needed
    // means the author wrote one.
    mrb_method_t init_m = {};
    bool init_irep = false;
    enum mrb_vtype live_tt = MRB_TT_OBJECT;

    // webmachine-ruby hands several callbacks one argument. A method that
    // declared the parameter must not be called with nothing.
    uint8_t node_argc[flow::kNodeCount] = {};

    struct ValueCb {
        bool has = false;
        mrb_sym sym = {};
        mrb_method_t m = {};
        bool irep = false;
        // mruby hands a cfunc its arguments through the callinfo the VM pushed,
        // so a cfunc called from a C++ frame reads a stranger's registers. Only a
        // function whose convention we set can be entered directly.
        NativeCb native = nullptr;
        bool on_class = false;
    };
    ValueCb cb_known_methods;
    ValueCb cb_allowed_methods;
    ValueCb cb_content_types_provided;
    ValueCb cb_content_types_accepted;
    ValueCb cb_options;
    ValueCb cb_variances;
    ValueCb cb_generate_etag;
    ValueCb cb_last_modified;
    ValueCb cb_expires;
    ValueCb cb_moved_permanently;
    ValueCb cb_moved_temporarily;
    ValueCb cb_post_is_create;
    ValueCb cb_create_path;
    ValueCb cb_base_uri;
    ValueCb cb_process_post;
    ValueCb cb_finish_request;

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
    // A resource reaches the body through kN11 (create_path or process_post)
    // or through kO14 and kP3 (content_types_accepted).
    static constexpr uint32_t kCbBodyReaders =
        kCbContentTypesAccepted | kCbCreatePath | kCbProcessPost;
    bool takes_body = false;
    // A body a callback may save goes to a file whatever its size, so
    // request.body.save is a link and never a second write.
    bool saves_body = false;
    std::vector<mrb_sym> body_readers;
    std::vector<mrb_sym> body_savers;
    // RFC 9110 15.5.14. -1 means this resource said nothing. The nearest
    // answer wins: the resource, then conf.max_body, then kMaxBodyDefault.
    long long max_body = -1;
    // Only the class form of content_types_accepted can be read at fold time.
    // An instance-level one is checked again when the flow reaches accept_helper.
    std::vector<std::string> sniff_types;

    // Never empty after fold: the default is [["text/html", :to_html]].
    struct TypedHandler {
        std::string type;
        mrb_sym handler = {};
        mrb_method_t m = {};
        bool irep = false;
        NativeCb native = nullptr;
        // A handler written as `def self.x` is asked once, at setup. `baked` is
        // what it answered.
        std::string baked;
        bool has_baked = false;
    };
    std::vector<TypedHandler> content_types_provided;

    // One struct, because a parked run takes the whole of it with it and
    // gives it back on the way in.
    struct RunState {
        mrb_value live = {};
        // The stop is between callbacks and never inside one, so nothing of a
        // Ruby stack is here.
        flow::Node stop_node = flow::Node::kB13;
        uint16_t stop_status = 0;
        int chosen = 0;
        // The konst tier and the error resource say no: a stop with nobody to
        // resume it is a hang.
        bool can_park = false;
        bool stopped = false;
        bool wants_body = false;
        // Set at the first node that reads content, so a walk that comes back does not stop twice.
        bool content_seen = false;
        bool answered = false;
        mrb_value answer = {};
        // The block is a value of this VM, so it never leaves this struct. What
        // leaves is the id the intern answers with.
        struct HeldTask {
            mrb_value block = {};
            mrb_value args = {};
            double deadline = 0.0;
            uint8_t what = 0;
        };
        HeldTask compute_task[kValueJobs];
        uint8_t compute_task_count = 0;
        // Undef until something is put there, so a run that never uses it
        // allocates nothing. The server never reads what is in it.
        mrb_value userdata = {};
        bool userdata_held = false;
        mrb_value watch[kValueJobs] = {};
        uint8_t watch_what[kValueJobs] = {};
        uint8_t watch_count = 0;
        bool values_started = false;
        const flow::ReqFacts *facts = nullptr;
        std::string *body = nullptr;
        bool have_body = false;
        // The error assets are mapped for the life of the process, so nothing is
        // rooted, copied or released for this handle.
        const AssetEntry *asset = nullptr;
        uint16_t status = 0;
        // 0 = never lend.
        size_t zc_min = 0;
        mrb_value zc = {};
        bool zc_have = false;

        std::string *headers = nullptr;
        const http::ReqValues *vals = nullptr;
        const ReqView *req = nullptr;
        uint16_t resp_code = 0;
        bool redirect = false;
        // Non-empty means the writer spells this Content-Type in a dynamic head.
        // There is no separate flag: a run needs its own head exactly when it
        // negotiated a Content-Type or produced a field line.
        std::string content_type;
        std::string disp_path;
        bool disp_set = false;
        // Nothing is opened here. The reactor opens it through the ring, so a
        // callback never blocks on a disk. file_bad answers 404 in the same shape
        // as a rejected resolve.
        std::string file;
        bool have_file = false;
        bool file_bad = false;

        // Asked at most once: g11, k13 and o18 share etag; h12, l17 and o18 share last_modified.
        bool etag_asked = false;
        bool etag_present = false;
        std::string etag_value;
        bool last_modified_asked = false;
        bool last_modified_present = false;
        int64_t last_modified_epoch = 0;
        bool expires_asked = false;
        bool expires_present = false;
        int64_t expires_epoch = 0;
        // Survives the run: re-resolving the handler's method per request is a
        // method search on the path that renders every body. marshal_ct rebuilds
        // only when the app's answer differs.
        std::vector<TypedHandler> content_types_provided;
        bool content_types_marshalled = false;
        std::vector<std::string> methods;
        std::vector<std::string> variances;
    };
    mutable RunState run;
    // What a `def self.x` answered, once, at setup. The value belongs to the
    // process, so no request enters the VM for it.
    struct KonstValue {
        bool asked = false;
        bool present = false;
        std::string text; // RFC 9110 8.8.3
        int64_t epoch = 0; // RFC 9110 5.6.7
    };
    KonstValue konst_etag;
    KonstValue konst_last_modified;
    KonstValue konst_expires;
    // One bit per kJob*. The flow never lets one of these choose an edge, so
    // all of them can be out at the same time.
    uint8_t value_jobs = 0;
    uint8_t value_watch = 0;
    bool has_caching = false;
};

void resource_fold(mrb_state *mrb, mrb_value klass, Resource &out_value);

struct RunAsk {
    const flow::ReqFacts &facts;
    const http::ReqValues *vals;
    const ReqView *req;
    size_t zc_min = 0;
    bool can_park = false;
};

struct RunAnswer {
    std::string *body;
    bool *have_body;
    std::string *headers;
};

// A stopped run keeps everything it wrote in res.run, and the caller takes it.
uint16_t resource_run(const Resource &resource, RunAsk request_ask, RunAnswer out_value);
struct RunRound {
    const std::array<mrb_value, kValueJobs> &answers;
    const std::array<uint8_t, kValueJobs> &what;
    uint8_t n;
};
// mruby catches what this raises. A std::out_of_range would pass the
// protect by and unwind the VM.
template <typename Array>
const typename Array::value_type &round_at(mrb_state *mrb, const Array &answer, size_t i)
{
    if (mrb_unlikely(i >= answer.size())) {
        mrb_raisef(mrb, E_INDEX_ERROR, "round entry %d of %d", static_cast<mrb_int>(i),
                   static_cast<mrb_int>(answer.size()));
        WM_UNREACHABLE();
    }
    return answer[i];
}
uint16_t resource_resume(const Resource &resource, RunAnswer out_value, const RunRound &round);
void resource_forget_userdata(const Resource &resource);
void resource_abandon(const Resource &resource, Resource::RunState &state);
bool run_stopped(const Resource &resource);

bool resource_exception_take(const Resource &resource, mrb_value *out_value);

// The connection holds the value until its send drains.
struct LentBody {
    mrb_value value;
    std::string_view bytes;
};
bool resource_body_lent(const Resource &resource, LentBody &out_value);

void resource_body_unlend(mrb_state *mrb, mrb_value value);

struct WantedFile {
    std::string_view name;
    bool bad;
};
bool resource_file_wanted(const Resource &resource, WantedFile &out_value);

void response_init(mrb_state *mrb, struct RClass *webmachine_module);
void response_bind(const Resource *resource);
class Assets;
void response_bind_error_assets(Assets *answer);

// A job is a C function over bytes: the VM is not thread-safe. What goes
// to a worker is the block, with its own arguments and deadline, so the
// stop lies between two flow nodes and no Ruby method is suspended mid-run.
struct ComputeTaskAsk {
    mrb_value block = {};
    mrb_value args = {};
    // Seconds. mruby-chrono spells it: 50.ms is 0.05.
    double max_runtime = 0.0;
};
bool compute_task_read_from_value(mrb_state *mrb, mrb_value value, ComputeTaskAsk *out_value);
void compute_task_init_class(mrb_state *mrb, struct RClass *webmachine_module);

void passwd_init_class(mrb_state *mrb, struct RClass *webmachine_module);

// A Ruby callback travels as its dumped irep, which every worker loads
// once. A native one travels as nothing: the pointer is the same number
// in every VM of this process.
struct ComputeTaskCode {
    std::string irep;
    double max_runtime = 0.0;
};
// A block carries no environment, so it cannot hold a database. The
// application registers how to build one, and every worker runs that once
// when it opens its VM. The key crosses as a string: an mrb_sym is a
// number one VM handed out.
struct WorkerBuild {
    std::string key;
    std::string irep;
};
bool worker_build_register(mrb_state *mrb, std::string key_name, mrb_value block);
const std::vector<WorkerBuild> &worker_builds();
void worker_builds_close();

inline constexpr unsigned kComputeTaskNoCode = ~0u;

// Not at fold: the class method builds its arguments out of the request,
// and add_route has no request. The first request pays one dump, 0.63 us
// measured.
unsigned compute_task_intern(mrb_state *mrb, mrb_value block, double max_runtime);
bool compute_task_code_of(unsigned stream_id, std::string *irep, double *max_runtime);

// The error log belongs to the reactor's thread, so a worker cannot write a failure down.
struct ComputeAnswer {
    std::string bytes; // CBOR
    bool raised = false;
    bool over_deadline = false;
    std::string exception;
    std::string step;
    std::string worker_name;
    uint64_t deadline_tag = 0;
};

class ComputePool
{
  public:
    ComputePool() = default;
    ~ComputePool()
    {
        stop();
    }
    ComputePool(const ComputePool &) = delete;
    ComputePool &operator=(const ComputePool &) = delete;

    // A pool that cannot be built refuses startup rather than falling back to the reactor's core.
    // One pool per process: the first ring to ask starts it, every later
    // ring shares it, and the first ring to go stops it.
    const char *start(unsigned workers, unsigned depth);
    void stop();

    // False means every slot is taken. A full submission queue is a raise
    // (sqe_or_raise). The answer goes to asker.
    bool submit(mrb_state *mrb, struct io_uring *asker, unsigned code_id, std::string_view arg,
                double deadline, uint64_t answer, uint64_t started);
    double started(unsigned slot, uint16_t generation);
    // mrb_vm_interrupt writes one word and reads none, so it is safe from
    // this thread.
    void interrupt(unsigned slot, uint16_t generation);
    bool slot_of_answer(uint64_t answer, unsigned *slot, uint16_t *generation) const;
    void name_deadline(unsigned slot, uint16_t generation, uint64_t timeout_tag);
    bool take(uint64_t answer, ComputeAnswer *out_value);
    unsigned workers() const;

    struct Impl;

  private:
    static void worker(Impl *impl, unsigned worker_number);
    Impl *impl_ = nullptr;
};

// The mask, the abort flag and the handle live in its CDATA and not in
// its iv table, which holds exactly what a GC has to see.
void watcher_init_class(mrb_state *mrb, struct RClass *webmachine_module);
bool value_is_watcher(mrb_state *mrb, mrb_value value);
unsigned watcher_events_mask(mrb_value value);
bool watcher_is_aborted(mrb_value value);
double watcher_timeout(mrb_value value);
bool watcher_deadline_passed(mrb_state *mrb, mrb_value value, mrb_value *said);
int watcher_fd(mrb_value value);
int watcher_slot(mrb_value value);
int64_t watcher_deadline_at(mrb_value value);
void watcher_set_deadline_at(mrb_value value, int64_t index);
// Points into the coroutine frame that parked.
Resource::RunState *watcher_run(mrb_value value);
void watcher_set_run(mrb_value value, Resource::RunState *run);
int watcher_job(mrb_value value);
void watcher_set_job(mrb_value value, int job);
void watcher_set_slot(mrb_value value, int slot);
void watcher_armed(mrb_value value, struct io_uring *ring, uint64_t poll_tag);
void watcher_unarmed(mrb_value value);
uint64_t watcher_armed_tag(mrb_value value);
void watcher_disarm(mrb_value value);
mrb_value watcher_source_of(mrb_state *mrb, mrb_value value);
mrb_value watcher_block_of(mrb_state *mrb, mrb_value value);
} // namespace webmachine

namespace webmachine::gzip
{
inline constexpr unsigned char kHeader[10] = {0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff};

// RFC 1951 / RFC 1952: level 1, raw deflate. False means serve identity.
bool compress(const std::string &incoming, std::string &out_value);
} // namespace webmachine::gzip

namespace webmachine
{
// No RFC maps a file's extension to a media type. It is the platform's
// database (mime.types / shared-mime-info), and the answer differs per host.
class MimeDb
{
  public:
    void load(mrb_state *mrb, const char *configured);
    const std::string &source() const
    {
        return source_;
    }
    size_t size() const
    {
        return by_ext_.size();
    }
    const char *type_of(const std::string &name) const;

  private:
    void take(const char *type, size_t tlen, const char *ext, size_t elen);
    void parse_types(const char *bytes, const char *text_end);
    void parse_globs2(const char *bytes, const char *text_end);

    std::vector<std::pair<std::string, std::string>> by_ext_;
    std::string source_;
};

// The stored fields carry PKWARE APPNOTE 4.3.7's names. The derived
// fields carry RFC 9110's:
//   etag           RFC 9110 8.8.3
//   last_modified  RFC 9110 8.8.2
//   content_type   RFC 9110 8.3
//   gzip_*         RFC 1952 2.2/2.3: the 10 header and 8 trailer octets
//                  that turn ZIP's raw deflate stream into a gzip member
// Each head remembers where its Date sits (RFC 9110 6.6.1) and which second it spells.
struct AssetEntry {
    std::string file_name;
    const char *file_data = nullptr;
    size_t compressed_size = 0;
    size_t uncompressed_size = 0;
    uint32_t crc32 = 0;
    bool deflated = false;
    bool last_modified_valid = false;
    char etag[10] = {};
    char last_modified[http::kDateLen] = {};
    std::string content_type;
    // APPNOTE 4.5: the pack's extra field 0x574D holds the whole <img> for this picture.
    const char *img_tag = nullptr;
    size_t img_tag_len = 0;
    // The pack's extra field 0x574E: this entry's Cache-Control value.
    std::string cache_control;

    // RFC 9112 2.1.
    struct Head {
        std::string bytes;
        size_t date_offset = 0;
        time_t unix_seconds = 0;
    };
    Head head_200[3]; // RFC 9110 15.3.1
    Head head_304[3]; // RFC 9110 15.4.5

    unsigned char gzip_header[10] = {};
    unsigned char gzip_trailer[8] = {};

    std::string h2_head_200; // RFC 9113 8.3 / RFC 7541
    std::string h2_head_304;
};

// The three prebuilt heads differ only in their Connection field line
// (RFC 9110 7.6.1), so they are not called variants: RFC 9110 12.1 means
// something else by that word.
class Assets
{
  public:
    enum ConnectionOption : uint8_t { kNoConnectionField = 0, kKeepAlive = 1, kConnClose = 2 };
    static constexpr const char *kConnectionLine[3] = {"", "Connection: keep-alive\r\n",
                                                       "Connection: close\r\n"};

    Assets() = default;
    ~Assets();
    Assets(const Assets &) = delete;
    Assets &operator=(const Assets &) = delete;

    void open(mrb_state *mrb, const char *zip_path, const MimeDb &mime);

    AssetEntry *find(const char *path, size_t length);

    struct AssetRequest {
        const flow::ReqFacts &facts;
        const http::ReqValues &vals;
    };
    uint16_t entry_verdict(const AssetEntry &entry, const AssetRequest &round) const;

    struct HeadAsk {
        AssetEntry &entry;
        uint16_t status_code = 0;
        ConnectionOption conn = kNoConnectionField;
        const char *date = nullptr;
        time_t unix_seconds = 0;
        size_t first_byte_pos = 0;
        size_t last_byte_pos = 0;
        const char *body_type = nullptr;
        size_t body_len = 0;
    };

    void head_answer(const HeadAsk &request_ask, std::string &sink);
    void answer_206_head(const HeadAsk &request_ask, std::string &sink);
    void answer_416_head(const HeadAsk &request_ask, std::string &sink);

    // RFC 1952 2.2: the deflate stream plus 10 header and 8 trailer octets.
    static size_t wire_len(const AssetEntry &entry)
    {
        return entry.deflated ? entry.compressed_size + 18 : entry.compressed_size;
    }
    // RFC 1952 2.2: a gzip member is three spans (our header, the mapping,
    // our trailer), so one window is up to three iovecs.
    struct Window {
        size_t off;
        size_t n;
    };
    static unsigned entry_wire_iov(const AssetEntry &entry, Window window, iovec *out_iov);
    static void entry_copy_wire(const AssetEntry &entry, Window window, std::string &out_value);

    std::vector<AssetEntry> &entries()
    {
        return entries_;
    }

  private:
    const AssetEntry *find_exact(const char *name, size_t length) const;
    struct DateStamp {
        const char *line;
        time_t unix_seconds;
    };
    static void head_patch_date(AssetEntry::Head &headers, DateStamp when);

    const char *map_addr_ = nullptr;
    size_t map_length_ = 0;
    std::vector<AssetEntry> entries_;
    AssetEntry::Head s405_[3]; // RFC 9110 15.5.6
    AssetEntry::Head s406_[3]; // RFC 9110 15.5.7
};

// 15 of the 54 statuses with a page are vendor inventions, and the page
// says so. XDG Base Directory Specification over FHS for the shipped pack.
std::string error_assets_path(const char *configured);

const char *status_title(uint16_t status);
const char *status_source(uint16_t status);

// Always there, never routed: the route that produced the error calls
// it, so an error is delivered by whoever made it.
class ErrorPages
{
  public:
    ErrorPages() = default;
    ~ErrorPages();
    ErrorPages(const ErrorPages &) = delete;
    ErrorPages &operator=(const ErrorPages &) = delete;

    void open(mrb_state *mrb, Assets *assets, Logger *elog);
    bool ready() const
    {
        return ready_;
    }

    int media_pick_for_status(uint16_t status, const char *accept, size_t length) const;
    const char *pack_body_of_status(uint16_t status, int slot, size_t *length) const;
    // Every 4xx names no failure and repeats nothing the client sent, so two
    // answers with the same status are the same bytes.
    const char *prepared_body(uint16_t status, int slot, size_t *length) const;
    const char *media_type_of_slot(int slot) const;
    bool accept_names_one_of_ours(const char *accept, size_t length) const;
    static bool accept_names_anything(const char *accept, size_t length);

    bool exception_text(mrb_value exc, std::string &out_value);

    // Nothing the client sent is in here. A page that repeated the target
    // would reflect a request into a document.
    struct Fields {
        const char *message = nullptr;
        size_t message_len = 0;
        const char *backtrace = nullptr;
        size_t backtrace_len = 0;
        const char *fingerprint = nullptr;
    };
    struct Page {
        uint16_t status;
        int slot;
        const Fields &fields;
    };

    bool render(const Page &bytes, std::string &out_value);
    // `held` is the caller's storage, used for the rendered case only.
    const char *body_of_page(const Page &bytes, std::string &held, size_t *length);

  private:
    struct Handler {
        mrb_sym sym = 0;
        std::string type;
        bool from_pack = false;
    };
    struct Cat {
        const AssetEntry *entry = nullptr;
    };
    void cats_read(Assets &assets);
    void prepared_pages_read();

    mrb_state *mrb_ = nullptr;
    mrb_value res_ = mrb_nil_value();
    mrb_sym exc_sym_ = 0;
    std::vector<Handler> have_;
    std::vector<std::string> types_;
    int plain_ = 0;
    int html_ = 0;
    static constexpr uint16_t kFirstError = 400;
    static constexpr uint16_t kPastLastError = 600;
    std::vector<Cat> cats_;
    std::array<int16_t, kPastLastError - kFirstError> cat_index_{};
    std::vector<std::string> prepared_;
    std::array<int16_t, kPastLastError - kFirstError> prep_index_{};
    bool ready_ = false;
    Logger *elog_ = nullptr;
};
} // namespace webmachine

namespace webmachine
{
// The names are the TOML keys, the CLI flags and the conf.* setters,
// verbatim. -1 means nobody said, because 0 is an answer an operator can give.
inline constexpr size_t kAllHeaderBytes = 8192;

// 128 KiB and not 64: measured through the real ring, 64 KiB gave +7.5%,
// inside the harness's own +/-10% spread, and 128 KiB gave +25%. At and
// below 32 KiB lending is a small net loss. 0 turns lending off.
inline constexpr size_t kZeroCopyDefault = 128u * 1024;

// The ring halves this until the kernel agrees. Named here because
// --write-config states it too.
inline constexpr unsigned kSqWanted = 32768;
// 1 GiB and not 2, so it fits an mrb_int on a 32-bit-integer build. The
// TOML range check is spelled in mrb_int, and a wrapped bound refuses every value.
inline constexpr size_t kZeroCopyMax = 1u << 30;

inline constexpr size_t kResponseFileWindow = 256u * 1024;

// The mmap/munmap pair is two syscalls the ring cannot carry. A file of
// one window is a single read and a single send, so a mapping replaces
// nothing below that. 0 is the operator saying "never map".
inline constexpr size_t kFileMapDefault = kResponseFileWindow;
// The same ceiling as kZeroCopyMax, for the same reason.
inline constexpr size_t kFileMapMax = 1u << 30;

// The page is built on the reactor thread, one stat per name, so the count bounds that work.
inline constexpr size_t kListingMax = 4096;

inline constexpr int kStandalonePort = 8080;

// RFC 9110 15.5.14. 1 MiB is nginx's client_max_body_size default, and
// Tomcat's maxPostSize is 2 MiB. The ceiling has to fit an mrb_int on a
// 32-bit-integer build.
inline constexpr size_t kMaxBodyDefault = 1u << 20;
inline constexpr size_t kMaxBodyMax = 1u << 30;

struct WsResource;
void ws_fold(mrb_state *mrb, mrb_value klass, WsResource &out_value);
WsResource *ws_resource_new();
void ws_resource_free(WsResource *round);
void ws_init(mrb_state *mrb, struct RClass *webmachine_module);
struct SseResource;
void sse_fold(mrb_state *mrb, mrb_value klass, SseResource &out_value);
SseResource *sse_resource_new();
void sse_resource_free(SseResource *round);
void sse_init(mrb_state *mrb, struct RClass *webmachine_module);

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
    std::vector<std::unique_ptr<WsResource, void (*)(WsResource *)>> ws_resources;
    RouteTable sse_table;
    std::vector<std::unique_ptr<SseResource, void (*)(SseResource *)>> sse_resources;
    mrb_value ready = mrb_nil_value();
    bool have_ready = false;
    mrb_value conf = mrb_nil_value();
    bool registered = false;
    // -1 = this app said nothing. The pack is one mount for the process,
    // so the first app with an opinion decides.
    int8_t disable_http_cats = -1;
    // -1 = this app said nothing.
    long long zero_copy_threshold = -1;
    // -1 = this app said nothing.
    long long file_map_threshold = -1;
    // -1 = this app said nothing.
    long long max_body = -1;
    // Empty = this app said nothing. The docroot is one anchor for the
    // process, so the first app that names one decides.
    std::string docroot;
    // Empty = this app said nothing, so the platform decides (TMPDIR, then
    // /tmp). A spilled body is linked into place when its temporary file and
    // its destination share a filesystem, and copied when they do not. /tmp is
    // tmpfs on most machines, so a body spilled there makes every placement a copy.
    std::string spill_dir;
    // Empty = this app said nothing. The pack is one mapping for the
    // process, so the first app that names one decides.
    std::string assets;
    std::string cert_path;
    std::string key_path;
    // RFC 6066 3: one pair per host name. The ClientHello's server_name picks between them.
    struct NamedPair {
        std::string host;
        std::string cert_path;
        std::string key_path;
    };
    std::vector<NamedPair> named_pairs;
    bool tls = false;
};

// The table is the WHATWG MIME Sniffing Standard's.
namespace sniff
{
enum class Verdict : uint8_t { kAgrees, kContradicts, kUnknown };
bool knows_media_type(std::string_view declared);
bool was_asked_for(const std::vector<std::string> &types, std::string_view declared);
size_t octets_needed();
Verdict check_declaration(std::string_view declared, std::string_view head);
} // namespace sniff

bool response_take_body(mrb_state *mrb, std::string_view sqe);
bool response_saves_body(mrb_state *mrb);

void application_init(mrb_state *mrb, struct RClass *webmachine_module);

void app_load(mrb_state *mrb, const char *path);

struct Registered {
    std::vector<AppSpec *> &specs;
    size_t max_listeners;
};
void app_registered_all(mrb_state *mrb, Registered out_value);

AppSpec *app_assets_only(mrb_state *mrb);
// Drops the VM's registry. Called before the VM closes.
void app_registry_release(mrb_state *mrb);

void app_listing(mrb_state *mrb);

void app_mark_bound(mrb_state *mrb, AppSpec &spec, const char *unix_path, int port);

void app_ready_run(mrb_state *mrb, AppSpec &spec);
} // namespace webmachine

namespace webmachine
{
// That fd is what RESOLVE_BENEATH anchors against. The kernel does the
// confinement, and this code does no path math of its own.
void docroot_open(mrb_state *mrb, const char *path);

void docroot_init(mrb_state *mrb, struct RClass *webmachine_module);

bool docroot_is_open();

int docroot_fd();
const char *spill_dir_get();
void spill_dir_set(const char *path);
bool body_file_slot_take();
void body_file_slot_give();
uint32_t body_file_slots_taken();

const char *docroot_path();

const struct open_how *docroot_how();

// The four standalone_* fields belong to the one application
// app_assets_only makes. Every other application names its listener, pack
// and docroot in its conf, so main.cpp refuses --unix, --port, --assets
// and --docroot beside --app.
struct ServerOptions {
    const char *error_assets_path = nullptr;
    const char *mime_types_path = nullptr;
    const char *log_path = nullptr;
    const char *log_privacy = nullptr;
    const char *error_log_path = nullptr;
    unsigned long long log_max_bytes = 500ull * 1024 * 1024;
    int stop_fd = -1;
    const char *app_path = nullptr;
    unsigned sq_entries = 0;
    // IORING_OP_MSG_RING carries a registered descriptor between two rings of
    // one process and nothing else does, which is why this is threads and not
    // processes.
    int threads = 1;
    int backlog = 0;
    int header_timeout = 0;
    int send_timeout = 0;
    int idle_timeout = 0;
    // -1 = nobody said; 0 = never lend.
    long long zero_copy_threshold = -1;
    // -1 = nobody said; 0 = never map.
    long long file_map_threshold = -1;

    bool standalone = false;
    const char *standalone_unix_path = nullptr;
    int standalone_port = 0;
    const char *standalone_assets_path = nullptr;
    const char *standalone_docroot_path = nullptr;
    bool standalone_listings = false;
};

void server_options(const ServerOptions &opts);

void server_say_which_backend();

void server_init(mrb_state *mrb, struct RClass *webmachine_module);

int server_run(mrb_state *mrb);

bool server_entered();

// mrb_close runs before a file scope object dies, so the owner of the VM
// calls this first.
void server_release();
} // namespace webmachine

namespace webmachine
{
// Nothing is defaulted here. Absence has to stay visible, or --flag and conf.* cannot beat it.
struct Config {
    std::string path;

    std::string unix_path;
    int port = 0;
    std::string app;
    std::string assets;
    std::string docroot;
    std::string mime_types;
    std::string error_assets;
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
    // 0 is a choice here (never lend), so absence is -1.
    long long zero_copy_threshold = -1;
    // -1 = nobody said; 0 = never map.
    long long file_map_threshold = -1;
};

// Written only on --write-config. False when the path already exists: it
// is never written over.
bool config_write_default(const char *path, const char *error_assets);

void config_load(mrb_state *mrb, const char *path, Config &out_value);
} // namespace webmachine

#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif

#endif
