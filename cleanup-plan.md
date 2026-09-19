# Cleanup plan

This plan says how the source of this tree becomes readable from its
declarations alone. It was written after a full read of `src/`,
`mrblib/`, `test/`, `bintest/`, `tools/` and `docs/`, and after a read
of the tables of contents of RFC 9110, 9111, 9112, 9113, 6455, 6265,
7541, 7692, 8441 and 9457.

The plan has four parts. Part 1 states the rules. Part 2 states the
target: the classes and the methods, in the order of the RFCs. Part 3
maps the present code onto that target and lists what is thrown away.
Part 4 states the steps, the order of the steps, and the check that
closes each step.

## 1. Rules

These rules add to CLAUDE.md. Where they meet, the stricter one holds.

1. **No comment in the source.** Not one line in `src/`, `mrblib/`,
   `test/`, `bintest/`, `tools/`, the Rakefile, the build configs or
   `mrbgem.rake`. A fact that a comment carried goes to one of four
   places: a name, a `static_assert` with a message, a test, or a page
   under `docs/`. Part 3.6 says which place for which fact.
2. **A declaration says what happens.** The function name says what
   the function does. Each parameter name says what is passed. The
   return type says what comes back. A reader who sees only the
   header knows the behaviour.
3. **Names come from the RFCs.** A field, a method, a status, a frame,
   an opcode and a close code carry the name the RFC gives them. A
   class is ordered as the RFC that defines it is ordered, and its
   methods follow the section order. A name this tree invented for an
   RFC thing is replaced.
4. **No method hides anything.** No function wraps one library call.
   No function changes an argument unless its name says so. No
   function raises unless its name says so. No function does two
   things.
5. **Every argument is const.** A function reads its inputs and
   returns its result. There is no `out_value`, no `&sink`, no pointer
   that is written through. What a function makes is its return type.
   A function that changes an object is a method of that object.
6. **Use what a linked library has.** `std::`, mruby, liburing,
   ls-hpack, zlib, miniz, picohttpparser, simdutf and ada are in the
   build. Nothing they answer is written here a second time. Part 3.3
   lists every second copy this tree holds today.
7. **One Resource takes one Request and gives one Response.** There is
   one Request type and one Response type. Every field of either is
   named as the RFC names it.

## 2. Numbers before the work

| what | count |
|---|---|
| lines in `src/` | 28362 |
| comment lines in `src/` (whole-line `//` only) | 3756 |
| structs, classes and enums in `src/` | 341 |
| function definitions in `src/*.cpp` | about 624 |
| Ruby-visible methods defined from C++ | 115 |
| Ruby methods in `mrblib/` | 31 |
| parameters named `out_value`, `out_answer`, `sink` or `out` in headers | 177 |
| parameter names that do not match the type or the value | more than 200 (Part 3.1) |
| code paths that walk the decision graph | 5 (Part 3.4) |
| request structs | 3: `ReqFacts`, `ReqValues`, `ReqView` |
| log record structs | 5: `LogRec`, `ErrRec`, `AccessLine`, `ErrorLine`, `ErrFacts` |
| route tables per application | 3: http, websocket, sse |
| responsibilities in `Ring<App>` (`ring.hpp`, 2290 lines) | 17 |
| responsibilities in `Http1` (`http1.hpp`, 2117 lines) | 16 |
| responsibilities in `http2.cpp` (2808 lines) | 16 |

Each number is measured again at the end of each step in Part 4.

## 3. Findings

### 3.1 Parameter names that say the wrong thing

A mechanical rename went wrong. The header declarations carry the
damage. Most definitions still carry the right name. Examples from
`src/webmachine.hpp`:

| line | declaration | what the parameter is |
|---|---|---|
| 153 | `Target to(Node count)` | the next node |
| 157 | `Target halt(uint16_t sqe)` | an HTTP status code |
| 424 | `eval_request(Node stream_id, const ReqFacts &round)` | a node and the request facts |
| 599 | `answer(const ReqFacts &request, Decided dynamic_body)` | the precomputed answers |
| 1165 | `fnv1a(uint64_t headers, const void *bytes, size_t count)` | the running hash |
| 1307 | `clen(const char *sqe)` | a C string |
| 1606 | `epoch_from_civil(Civil conn)` | a calendar date |
| 1590 | `etag_list_match(EtagMatch method)` | a tag list and a tag |
| 1625 | `choose_media_type(Conneg conn)` | the offered types and the Accept value |
| 1637 | `uri_join(UriRef round, std::string &out_value)` | a base and a reference |
| 1958 | `define_native(mrb_state *mrb, struct RClass *conn, Native count)` | a class and one native method |
| 2637 | `ws_resource_free(WsResource *round)` | a resource |
| 2705 | `response_take_body(mrb_state *mrb, std::string_view sqe)` | the body bytes |
| 2562 | `render(const Page &bytes, std::string &out_value)` | a page description |
| 2461 | `entry_verdict(const AssetEntry &entry, const AssetRequest &round)` | the request |

The five audit reports found the same in every file. The words that
were sprayed in are `count`, `sqe`, `round`, `conn`, `headers`,
`bytes`, `field`, `text`, `window`, `retry`, `stream_id`, `poll_tag`,
`index`, `method`, `answer`, `group`, `dynamic_body`, `block`, `one`,
`other`, `status_text`, `error_message`, `writer`, `prefix_variants`.
Local variables carry them too: `http1.cpp:1133` names a time
`status_text`, `http1_class.cpp:275` names a hex digit
`dynamic_body`, `http1.cpp:1862` names a route index `writer`.

`tools/rename-symbol.py` has a form that finds a symbol by the first
text match of its name in a file. In a 3000-line file the first match
is rarely the symbol meant. clangd then renames the wrong symbol, and
the result compiles. That form is deleted (Part 4, step 1).

### 3.2 Argument packs and vague type names

Sixty-two structs exist only to carry the arguments of one call. Each
has a name that says nothing about what is inside:

`Given`, `Walk`, `Decided`, `Shortcut`, `FactSink`, `Field`,
`HeaderList`, `RunAsk`, `RunAnswer`, `RunRound`, `Raised`,
`Registered`, `LentBody`, `WantedFile`, `UriRef`, `EtagMatch`,
`Conneg`, `RangeField`, `HeadAsk`, `Window`, `DateStamp`,
`AssetRequest`, `Page`, `Fields`, `WsAdmit`, `Negotiated`, `Sink`,
`Lending`, `Parked`, `H2Sending`, `SseBegin`, `WsUpgrade`, `H1Head`,
`BoundAsk`, `BoundOut`, `BoundPrep`, `BoundStart`, `Spelling`,
`FileHead`, `H2ErrorAsk`, `H2SseAsk`, `H2WsAsk`, `H2Asset`,
`Assembled`, `SpelledHead`, `WireSink`, `Completed`, `Slot`, `On`,
`Wanted`, `SetupCall`, `Folding`, `Asked`, `At`, `Bound`, `Param`,
`Want`, `ResumeAsk`, `Thrown`, `FeedCall`, `SaveAsk`, `Form`.

Some of them are the same shape twice: `H2WsAsk` and `H2SseAsk` have
the same seven fields; `Asked` and `NamedSym` are the same pair;
`ws::Frame` repeats four fields of `ws::Head`; `Resolved` and `Bound`
differ by one flag.

Under rule 5 most of these disappear. A function that returned its
result needs no `RunAnswer`, `BoundOut`, `WsAdmit`, `Negotiated`,
`Parked` or `Raised`. A function with three const arguments needs no
pack. A pack that survives is a real value and is named as one:
`ByteRange`, `MediaType`, `FieldLine`.

Other names that say nothing or say the wrong thing: `Held` (three
times, in `http1.hpp`, `ring.hpp` and `RunState::HeldTask`),
`Round` (two unrelated types, `Http1::Round` and `Conn::Round`),
`Bundle`, `konst`, `KonstSet`, `KonstAnswers`, `KonstValue`,
`Conn::Slow`, `ConnFailed` (an exception), `Released`, `Seen`,
`HeldList` (four scope guards for one job), `BootQueue` (it is the
reactor's ring too), `Method` in `wsconn.cpp` (a class and a symbol,
where every other file means an HTTP method), `Data` in `H2Stream`
(a destination, not data), `H2Control` (any frame), `RoundOut` (a
writer), `stream` in `Http1` (lowercase, and not a stream).

House words that are not English and not RFC: `fold` (compile a
class into a table), `park` (suspend a coroutine), `lend` (send
without a copy), `spell` (format), `say` (print), `konst` (constant),
`bake` (compute once at start), `cat` (an error page picture). Each
gets the plain word.

### 3.3 Second copies of what a library has

| this tree wrote | the library has |
|---|---|
| `RouteSpans::Span`, `Borrowed`, `Seg` (twice), every `const char *x; size_t x_len;` pair in `ReqValues`, `ReqView`, `ErrFacts` | `std::string_view` |
| `Held` (copy a head and rebase every pointer), `follow_copy`, `rebase`, `kReqValueSpans` and its size assert | offsets into one buffer; nothing to rebase |
| `clen` | `std::string_view::size` |
| `ClaimedLength` | `std::optional<size_t>` |
| `Released`, `Held`, `Seen`, `HeldList` | one scope guard |
| `Rearm`, `H2Block`, `Slot` | the one field each holds |
| `MemWriter`, `FileWriter` | the sink itself |
| `H2BlockOut` | `std::span<unsigned char>` and a returned count |
| `hpack_length_spell`, `hpack_name_index_spell`, `h2_build_block`, `h2_build_asset_blocks`, `h2_build_asset_shared`, the 206 and 416 arms, `H2State::enc_ins`, the head cache invalidation | ls-hpack, which is linked and already drives `h2_enc_field` |
| `u32_put`, `h2_u32`, `h2_u16` | `htonl`, `ntohl`, `ntohs`, `std::memcpy` |
| `tok_eq`, `ci_eq`, `ascii_same`, `text_is_same_ignoring_case`, `sniff::media_type_is_same` | one `tok_eq`; the other four are copies |
| three lowercase loops (`string_copy_lowercased`, `request.cpp:233`, `request.cpp:673`) | one function, or `std::ranges::transform` |
| `text_trim_optional_space`, the trims in `request.cpp:794` and `response.cpp:89` | `find_first_not_of`, `find_last_not_of` |
| `read_size`, `parse_content_length`, `read_fixed_digits`, `window_bits`, `ws_version`, the hex loop in `chunk_lines_ok`, `text_to_whole_number`, `sscanf` in `cats_read`, `kernel_shortens_bundle_entries`, `raise_nofile` | `std::from_chars` |
| `write_two_digits`, `spell_content_length`, `hex8_spell`, the hex loop in `request.cpp:373`, `snprintf` in `sse.cpp`, the status digits in `head_spell` and `build_one_variant` | `std::to_chars` |
| `epoch_from_civil`, `Civil` | `std::chrono::sys_days{year/month/day}` |
| `date_core` | `std::format("{:%a, %d %b %Y %H:%M:%S} GMT", sys_seconds)` |
| `parse_http_date` | stays ours until the toolchain has `std::chrono::parse` (GCC 14); then it goes |
| `min`, `max` and `clamp` as ternaries (more than 30 places) | `std::min`, `std::max`, `std::clamp` |
| `H2State::find`, `H2State::close_stream` loops | `std::find_if`, `std::erase_if` |
| `ByFileName`, `NameBeforeKey`, `ExtBefore`, `SameExt`, `ExtBeforeKey` | `std::ranges::sort` and `lower_bound` with a projection |
| `entry_crc_is_right` | `mz_zip_validate_mem_archive` |
| `extra_field_find` in C++ and two copies in the Rakefile | one reader of APPNOTE 4.5.2 |
| `entry_wire_iov` and `entry_copy_wire` | one function that yields the three segments |
| `path_is_regular_file`, `save_make_directory`, `body_copy_to_path` (memory arm), `file_read_whole_or_absent` | `std::filesystem` |
| `accept_member_edge`, `accept_holds_media_type`, `accept_names_anything`, `accept_names_one_of_ours` | `choose_media_type`, which the same function already calls |
| `media_type_base`, `media_type_params`, `param_take_next`, `param_find_named`, `media_params_agree`, `media_type_pattern_matches`, `media_type_without_parameters` | one media type parser |
| `kFaces`, `status_title`, `status_source` | `reason(status)` |
| `access_log_method_name`, `kMethodName[]`, the switch in `request.cpp:77` | one method name table |
| `chunk_tchar` and `is_tchar`; OWS tested five ways | one `tchar` and one `ows` predicate |
| the private chunked-body walk (`ChunkScan`, `chunk_lines_ok`, `chunk_size_line_ok`) beside `phr_decode_chunked` | one decoder (open decision 3, Part 5) |
| `base64_encode_digest` | `simdutf::binary_to_base64` |
| `utf8_prefix_may_still_be_valid` | simdutf's `TOO_SHORT` count |
| `handler_call_with_no_args` and `handler_call_in_protected_call` | one trampoline with an argc |
| `exception_text`'s join loop | `mrb_ary_join` |
| `yield_array_entries` | `mrb_yield_argv` over `RARRAY_PTR` with the arena saved |
| about 90 `std::string_view(RSTRING_PTR(v), RSTRING_LEN(v))` sites and every `mrb_str_new(mrb, p, n)` return | mruby-c-ext-helpers. CLAUDE.md says it is in the build. It is not: `mrbgem.rake` does not name it. It is added in step 1. |
| `Config.check_whole_number` and `Config.check_text` in Ruby | the same bounds checked again in `application.cpp` |
| hand pointer arithmetic | `std::string_view`, `std::span`, `std::distance`, `std::next`. Every C++ file breaks CLAUDE.md here. |

### 3.4 Five walkers of one graph

The decision graph is one table, `kFlow`. Five pieces of code walk it:

1. `flow::walk` (`webmachine.hpp:489`), constants only, no Ruby.
2. `flow::answer` (`webmachine.hpp:600`), the shortcut in front of 1.
3. `run_engine` (`resource.cpp:1486`), with Ruby, with suspend and
   resume. Its fall-through tail repeats the loop body of 1.
4. `walk_compiled` and `status_reached_from` (`webmachine.hpp:608`),
   a template unrolling with no caller outside five `static_assert`s
   that repeat five earlier `static_assert`s.
5. `lands_on`, `reaches_a_node_that_reads_the_request`,
   `shortcut_for`, `block_skips_are_the_graphs`, each with its own
   copy of the test `kind == kRequest || node == kC4`.

One walker serves. The speed of the constant tier does not come from
a second walker. It comes from a status that was computed once, at
route time, for the plain request of each method. That table stays.
The one walker computes it at route time.

### 3.5 One request under three names, and the Ruby surface

`ReqFacts` holds the booleans the graph reads. `ReqValues` holds
pointers to the field values. `ReqView` holds the target, the method
and the content. All three describe one request. One `Request` holds
all of it, as offsets into the one head buffer, so nothing is rebased
when the buffer moves.

On the Ruby side one field is reachable under several names:

- `content_type`, `content_length`, `authorization`, `accept`,
  `accept_encoding`, `if_match`, `if_none_match`,
  `if_modified_since`, `if_unmodified_since`, `host`: each is also
  `headers['name']`.
- `method` is also `get?`, `head?`, `post?`, `put?`, `delete?`,
  `options?`.
- `uri`, `path`, `disp_path`, `path_tokens`, `path_info`,
  `query_string`, `base_uri`: seven readings of the request target
  and the Host field.
- `do_redirect` and `redirect_to` are one C function bound twice.
- A Location is set three ways. A status is set two ways. A body is
  named five ways.
- `response.error` and `response.userdata` are slots the server never
  reads.
- `has_body?` and `body` disagree on an empty body.

`request` is defined on three classes from one C function. The
websocket and sse resources define no method from C; their callback
names are found by search in the fold.

Which of the invented names stay is open decision 1 (Part 5).

### 3.6 Where the facts in the comments go

3756 comment lines were read. They hold four kinds of fact, and each
kind has one destination.

| kind | example | destination |
|---|---|---|
| an RFC clause | `// RFC 9110 13.1.3: a date in the future is ignored (l15)` | the namespace and the function name: `rfc9110::preconditions::if_modified_since_in_the_future_is_ignored`; and a test whose name cites the clause |
| a measured number | `kLendFloor = 4096`, the `sendmsg` cost, the 128 KiB zero-copy default | `bench/results/` already holds the row; `docs/explanation/` gets one page, `numbers-that-were-measured.md`, that lists each constant, its value, the row it came from and the script that moves it |
| a kernel or library quirk | `EINTR` on `close(2)`, io-wq affinity, `MSG_RING` between rings, `mrb_noreturn` under `-std=c++20`, `MRB_FUNCALL_ARGC_MAX` | a name (`close_ignoring_eintr`), or a `static_assert` where it is a constant, or `docs/explanation/reactor.md` where it is a design fact |
| a bug that was fixed | `// A guard that returns instead of raising hides our own bug` | a test in `test/` or `bintest/` that fails when the bug returns |

A comment that is none of the four is deleted with nothing kept. That
is most of them: they restate the code below them.

Two comments are already false today: `wsconn.cpp:884` names
`take_pending`, which no longer exists; `wsconn.cpp:272` describes an
arity check that the next comment says does not happen. Two comments
each claim to be the only writer of a field line (`resource.cpp:598`,
`response.cpp:115`).

### 3.7 Dead code

No caller anywhere in the tree:

`Http1::swap_assets`; the `Http1(const RouteTable &, ...)`
constructor; `Ring::deliver` and with it `finish_round`;
`Ring::plan_drop_front`; `Ring::live_conns`; `Ring::max_conns`;
`boot_queue_down`; `Conn::kMsgIovMax`; `RingConfig::rings_in_process`
(written, never read); `kTlsUlp`, `kTlsTx`, `kTlsRx`, `kTlsBye`,
`kTlsTxKey`; `WM_H2_LOG_DEFINED`; `walk_compiled` and
`status_reached_from`; `body_file_slots_taken` (a test reads it, the
server does not); the second copy of the ten `ws_*` and `sse_*`
declarations at `http1.hpp:563`; the three empty namespace blocks in
`http1_wire.cpp`; `test/conformance` (an empty file); the unused
`#include <simdutf.h>` in `test/wm_ruby.cpp`.

`tools/comment-anchors.sh` and its baseline: nothing runs it, its
baseline is in a format its own reader cannot parse, and after this
plan it measures an empty set.

### 3.8 Files that hold more than one thing

- `http1_wire.cpp` holds only WebSocket code.
- `http1_members.cpp` holds the body spill and the h2 connection
  state.
- `http2.cpp` holds `Http1::pending` and `Http1::spell_next_round`,
  which carry the h1 paths.
- `ring_setup.hpp` holds rlimit code, ring bring-up and the operation
  tag enums, which belong with `Op`.
- `webmachine.hpp` (2842 lines) holds the graph, the router, the
  logger, the passwd record, the http helpers, the request, the
  resource, the compute pool, the watcher, gzip, mime, assets, error
  pages, the application spec, sniff, docroot, server options and
  config. One change recompiles the tree.

## 4. The target, in the order of the RFCs

Namespaces are named by the RFC. A file is named for what is in it.
The RFC number in the namespace is the link a comment used to carry.
Inside a namespace the order of the declarations is the order of the
RFC's sections. A reader with the RFC open finds the code in the same
place.

Every function below takes const arguments and returns its result.
Every name below is a proposal for the skeleton commit (step 2). The
skeleton is reviewed before code moves under it.

### 4.1 `rfc9110` (HTTP Semantics)

```
namespace rfc9110 {

// 5 Fields
struct FieldLine { std::string_view name; std::string_view value; };
class Fields {                      // ordered list of FieldLine
  std::optional<std::string_view> first(std::string_view name) const;   // 5.2
  std::string combined(std::string_view name) const;                    // 5.2, comma list
  std::vector<std::string_view> all(std::string_view name) const;       // 5.3
  Fields with(FieldLine line) const;
  Fields without(std::string_view name) const;
};
bool field_name_is_token(std::string_view name);                       // 5.1, 5.6.2
bool field_value_has_no_cr_lf_nul(std::string_view value);             // 5.5
bool token_equals_ignoring_case(std::string_view a, std::string_view b); // 5.1 (was tok_eq)
std::optional<std::chrono::sys_seconds> parse_http_date(std::string_view text); // 5.6.7
std::string format_imf_fixdate(std::chrono::sys_seconds at);           // 5.6.7

// 6 Message abstraction
enum class Method { GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, other }; // 9
struct Request {                    // 6.2 control data, 6.3 fields, 6.4 content
  Method method;
  std::string_view method_token;
  std::string_view target;          // RFC 9112 3.2 / RFC 9113 8.3.1
  std::string_view path;            // RFC 3986 3.3
  std::string_view query;           // RFC 3986 3.4
  Fields fields;
  Content content;                  // bytes in memory or a file descriptor, and the declared length (8.6)
  bool tls;
  // 7.2
  std::string_view host() const;
  // 10.1, 11.6.2, 12.5, 13.1, 14.2: one accessor per field the server reads, named as the field
  std::optional<std::string_view> authorization() const;
  std::optional<std::string_view> accept() const;
  ...
};
struct Response {                   // 6.2 status, 6.3 fields, 6.4 content
  uint16_t status;
  Fields fields;
  Body body;                        // owned bytes, a lent Ruby string, a file, or an asset
};

// 8 Representation data and metadata
std::string content_type_with_charset(std::string_view media_type);    // 8.3.2
bool media_type_is_compressible(std::string_view media_type);          // 8.4.1.3 + RFC 6839
std::optional<std::string> gzip(std::string_view bytes);               // 8.4.1.3
std::optional<size_t> parse_content_length(std::string_view value);    // 8.6
enum class Validator { strong, weak };
bool entity_tag_matches(std::string_view tag, std::string_view list, Validator how); // 8.8.3.2
std::string quote_entity_tag(std::string_view raw);                    // 8.8.3

// 10 Message context
std::string allow_field_value(std::span<const Method> allowed);        // 10.2.1
std::string resolve_location(std::string_view base, std::string_view reference); // 10.2.2 + RFC 3986 5.3

// 12 Content negotiation
std::optional<size_t> choose_media_type(std::span<const std::string> offered, std::string_view accept); // 12.5.1
bool gzip_is_acceptable(std::string_view accept_encoding);             // 12.5.3
std::string vary_field_value(...);                                     // 12.5.5

// 13 Conditional requests
struct Preconditions { ... the five fields, parsed };                   // 13.1
std::optional<uint16_t> evaluate_preconditions(const Preconditions &p, const Validators &v, Method m); // 13.2

// 14 Range requests
struct ByteRange { size_t first; size_t last; };
enum class RangeResult { none, one, unsatisfiable };
std::pair<RangeResult, ByteRange> parse_byte_range(std::string_view range, size_t complete_length); // 14.1.2
bool if_range_matches(std::string_view if_range, std::string_view etag); // 13.1.5

// 15 Status codes
std::string_view reason_phrase(uint16_t status);                       // 15
}
```

What moves here: `tok_eq`, `star_value`, `path_only`, `parse_method`,
`with_charset`, `compressible_media_type`, `reason`, `date_core`,
`spell_content_length`, `parse_content_length`, `NamedFieldIndex`,
`header_switch`, `parse_range`, `if_range_matches`,
`gzip_acceptable`, `etag_list_match`, `parse_http_date`,
`choose_media_type`, `accept_is_exact`, `etag_spell`, `uri_join`,
`field_name_is_the_servers`, `field_name_ok`, `field_value_ok`,
`join_repeated_fields`, `gzip::compress`, and from `resource.cpp` the
media type parser and `run_append_allow`.

What is thrown: everything in Part 3.3 that this namespace replaces,
the SWAR word helpers (`std::string_view::find_first_of` is the same
speed for this length; `bench/instructions.sh` confirms or refutes
that in step 5), `ReqFacts`, `ReqValues`, `ReqView`,
`kReqValueSpans`, `rebase`, `follow_copy`, `Held`.

### 4.2 `rfc9111` (Caching)

```
namespace rfc9111 {
bool freshness_is_stated(const rfc9110::Fields &response_fields);     // 4.2.1, 5.2, 5.3
constexpr std::string_view no_cache_directive = "no-cache";            // 5.2.2.4
bool target_names_a_directory(std::string_view target);                // 4.2.2, heuristic freshness
}
```

### 4.3 `rfc9112` (HTTP/1.1)

```
namespace rfc9112 {
class Connection {
  // 2 Message, 3 Request line, 5 Field syntax
  ParseResult parse_head(std::string_view bytes) const;                // through picohttpparser
  // 6 Message body
  BodyLength body_length(const rfc9110::Request &r) const;             // 6.3
  // 7.1 Chunked transfer coding
  ChunkedResult decode_chunked(std::string_view bytes) const;
  // 8 Incomplete messages
  // 9 Connection management
  bool persists(const rfc9110::Request &r) const;                      // 9.3
  std::string serialize(const rfc9110::Response &r, Persistence p) const; // 2.1 status line + fields
};
}
```

What moves here from `http1.cpp`, `http1_class.cpp`, `http1.hpp`:
`feed_parse`'s head loop, `wire_header_read`,
`transfer_encoding_fold`, `connection_field_holds_token`,
`head_framing_status`, `WireFacts`, `take_body`, `take_chunked`,
`BodySpill`, `head_spell`, `answer_assemble`, `assemble_dynamic`,
`build_*` of the prebuilt store, `patch_date`, `Preface`,
`h1_preface`, `h1_upgrade_or_stream`.

What does not belong to HTTP/1.1 and moves elsewhere: the docroot
file transfer (`FileXfer`, `FileStep`, sixteen `file_*` methods),
the asset answers, the coroutine suspend and resume, the compute and
watcher bridges, the zero-copy plan, the error pages, sniffing. Each
goes to its own class in Part 4.9.

### 4.4 `rfc9113` (HTTP/2) and `rfc7541` (HPACK)

```
namespace rfc9113 {
enum class FrameType : uint8_t { DATA = 0x0, HEADERS = 0x1, ... CONTINUATION = 0x9 }; // 6
enum class ErrorCode : uint32_t { NO_ERROR = 0x0, PROTOCOL_ERROR = 0x1, ... };         // 7
enum class Setting : uint16_t { HEADER_TABLE_SIZE = 0x1, ... };                        // 6.5.2
struct FrameHeader { uint32_t length; FrameType type; uint8_t flags; uint32_t stream_id; }; // 4.1
FrameHeader parse_frame_header(std::span<const unsigned char, 9> octets);
std::array<unsigned char, 9> serialize_frame_header(FrameHeader h);

class Stream {                       // 5.1 states, 5.2 flow control window
  State state; int64_t send_window; int64_t receive_window; ...
};
class Connection {
  // 3.4 preface, 4.3 field section compression (ls-hpack only), 5 streams,
  // 6 frames one method per frame type, 8 HTTP semantics: 8.2.1 field validity,
  // 8.2.2 connection-specific fields, 8.2.3 Cookie, 8.3.1 request pseudo-headers
  ...
};
}
```

What is thrown: every hand-built HPACK block and the static-table
indices (`0x88`, `8`, `18`, `26`, ...). ls-hpack encodes every field.
`H2State::enc_ins` and the head cache go with them, unless step 6's
instruction count says the cache paid for itself; then the cache is
rebuilt on top of ls-hpack, not beside it.

What moves out: WebSocket over h2 (RFC 8441) to 4.5, SSE over h2 to
4.7, the h1 paths in `spell_next_round` to 4.3.

### 4.5 `rfc6455` (WebSocket), `rfc7692` (permessage-deflate), `rfc8441`

```
namespace rfc6455 {
std::array<char, 28> sec_websocket_accept(std::string_view sec_websocket_key); // 4.2.2
enum class Opcode : uint8_t { continuation = 0x0, text = 0x1, binary = 0x2, close = 0x8, ping = 0x9, pong = 0xA }; // 5.2
struct FrameHeader { bool fin; bool rsv1; Opcode opcode; bool masked; uint64_t payload_length; std::array<unsigned char,4> masking_key; }; // 5.2
std::optional<FrameHeader> parse_frame_header(std::span<const unsigned char> octets);
size_t serialize_frame_header(FrameHeader h, std::span<unsigned char, 14> out);
std::string unmask(std::string_view payload, std::array<unsigned char,4> key, size_t offset); // 5.3
enum class CloseCode : uint16_t { normal_closure = 1000, going_away = 1001, protocol_error = 1002, ... }; // 7.4.1
struct Close { CloseCode code; std::string_view reason; };                       // 5.5.1
class Connection { ... 5.4 fragmentation, 5.5 control frames, 6 send/receive, 7 close ... };
}
namespace rfc7692 {
struct Parameters { bool server_no_context_takeover; bool client_no_context_takeover; uint8_t server_max_window_bits; uint8_t client_max_window_bits; }; // 7.1
std::optional<Parameters> negotiate(std::string_view sec_websocket_extensions);   // 5, 7.1
class Codec { ... 7.2 };
}
```

`ws::Head` and `ws::Frame` become one `FrameHeader`. `ws::Message`
becomes the reassembly state of `Connection`. `WsAdmit` and
`Negotiated` go under rule 5.

### 4.6 `rfc6265` (Cookies) and `rfc9457` (Problem Details)

```
namespace rfc6265 {
std::vector<std::pair<std::string_view, std::string_view>> parse_cookie(std::string_view cookie_field); // 4.2
std::string set_cookie_field_value(std::string_view name, std::string_view value, const Attributes &a); // 4.1
}
namespace rfc9457 {
struct ProblemDetails { std::string type; uint16_t status; std::string title; std::string detail; std::string instance; }; // 3.1
}
```

### 4.7 `whatwg` (Server-Sent Events, MIME sniffing)

```
namespace whatwg {
class EventStream { std::string event(std::string_view name, std::string_view data) const; std::string comment_line() const; ... };
enum class SniffVerdict { agrees, contradicts, unknown };
SniffVerdict sniff(std::string_view declared_media_type, std::string_view first_octets);
constexpr size_t sniff_octets = 512;
}
```

### 4.8 `webmachine` (the decision graph and the Resource)

```
namespace webmachine {
enum class Node : uint8_t { B13, B12, ... P11 };            // the letters of the diagram, unchanged
struct Edge { Node node; Kind kind; std::string_view callback; Target on_true; Target on_false; };
inline constexpr Edge graph[] = { ... };                    // kFlow without the clause string: nothing reads it, so it is a comment; each clause becomes the name of that edge's case in test/wm_flow.rb

struct Callback { mrb_sym name; mrb_method_t method; bool is_irep; NativeCallback native; bool on_class; uint8_t argc; };
struct Resource {
  std::array<Callback, node_count> node_callback;           // was six parallel arrays
  std::array<Callback, value_count> value_callback;         // was sixteen ValueCb fields and a bit mask
  std::array<uint16_t, method_count> plain_request_status;  // was KonstSet: the status of a request with no negotiation and no precondition, computed once
  ...
};
Resource compile_resource(mrb_state *mrb, mrb_value klass);  // was resource_fold
struct Walk { Node at; uint16_t status; ... };
WalkResult walk(const Resource &r, const rfc9110::Request &q, WalkState state); // the one walker
}
```

`RunState` (60 fields) is split three ways: what the walk carries
(`WalkState`), what the response holds (`rfc9110::Response`), and
what is suspended (`SuspendedWalk`: the coroutine handle and its
pending jobs). Nothing else of it survives.

### 4.9 Not in an RFC: the server

These are the parts of the tree no RFC describes. Each is one class
with one job. The list follows the boot order.

| class | job | comes from |
|---|---|---|
| `Config` | the TOML file, the flags and `conf.*`, merged; absence stays visible | `config.cpp`, `ServerOptions`, `AppSpec` settings |
| `Application` | the routes of one app and its listener | `application.cpp`, `AppSpec` |
| `Router` | one route table with a resource kind per route | three `RouteTable`s |
| `Reactor` | the io_uring loop: submit, complete, dispatch | `Ring<App>` minus the eight below |
| `OperationTable` | in-flight operations and the kernel refcount | `Op`, `arm`, `hold`, `release` |
| `BufferRing` | provided buffers | `pool_`, `buf_ring_`, `replenish_` |
| `Listener` | socket, bind, listen, accept, hand to a thread | `setup_listener`, `place_of_next_peer` |
| `FileReader` | openat2, statx, read, mmap of a docroot file | `FileIo`, `FileXfer`, `file_*` |
| `LogWriter` | the access log and the error log over the ring | `Logger`, `flush_*`, `arm_error_write` |
| `ComputeBridge` | jobs to the worker rings and their deadlines | `on_compute_*`, `Deadline` |
| `WatchBridge` | poll on a foreign descriptor and its deadline | `watcher_*` |
| `ComputePool` | the worker threads and their VMs | `compute_task.cpp` |
| `Watcher` | the Ruby-visible watch handle | `watcher.cpp` |
| `AccessLogLine`, `ErrorLogRecord` | the two records the daemon reads | `LogRec`, `ErrRec`, `AccessLine`, `ErrorLine`, `ErrFacts` |
| `Assets` | the ZIP pack, mapped once | `assets.cpp` |
| `ErrorPages` | one page per status, rendered at boot | `error_assets.cpp` |
| `Docroot` | the confined directory | `docroot.cpp` |
| `MimeTypes` | extension to media type | `mime.cpp` |
| `PasswordFile` | LMDB and argon2id | `passwd.cpp` |
| `Fingerprint` | FNV-1a over the error facts | `fnv1a*`, `spell_fingerprint` |

## 5. Open decisions

Each decision changes what the skeleton looks like. The recommended
answer is first.

1. **Invented Ruby names.** `disp_path`, `path_info`, `path_tokens`,
   `do_redirect`, `is_redirect?`, `base_uri`, `has_body?`,
   `response.error`, `response.userdata`, `get?` ... `options?`.
   Recommended: keep `path_tokens` and `base_uri` (webmachine-ruby
   apps use them), drop the rest, and say so in
   `docs/reference/request-and-response.md`. Alternative: keep all as
   one-line Ruby methods in `mrblib/`, defined once, on top of the RFC
   names.
2. **The precomputed plain-request status.** Recommended: keep it as
   a table the one walker fills at route time. The measured gain of
   the constant tier lives there. Alternative: drop it and read the
   loss in `bench/instructions.sh`.
3. **Two chunked decoders.** Recommended: run the bintests that made
   the strict walk exist against `phr_decode_chunked` alone. If one
   fails, ours stays and the call into picohttpparser goes. If none
   fails, ours goes. One decoder either way.
4. **Namespaces named by RFC.** Recommended: yes. It is the one place
   a clause reference survives without a comment.
5. **The h2 head cache.** Recommended: delete with the hand-built
   HPACK, then measure. Rebuild on ls-hpack only if the count says so.
6. **`webmachine-ruby` callback names.** They stay. They are the
   contract an app is written against, and the graph table cites them.

## 6. Steps

Each step is one pull request. Each step ends with the check named
under it. The suite (`rake test`) and the ship smoke
(`rake ship_smoke`) run in CI for every step. Nothing may fail. The
instruction count (`bench/instructions.sh`) runs at the end of each
step and is compared to step 0. A step that raises it by more than
one percent is discussed before merge.

This container has no liburing and no mruby checkout, so the checks
run in CI or on the author's machine, not here.

### Step 0: the baseline

- `rake test` green on `next`.
- `bench/instructions.sh` for the h1 floor, the h2 floor and one
  asset. The three counts go to `bench/results/` with the commit hash.
- The numbers of Part 2 go into the pull request text of every later
  step, measured again.

### Step 1: remove the dead, fix the tools

- Delete everything in Part 3.7.
- Delete the name form of `tools/rename-symbol.py`. The position form
  stays. `rename-batch.py` gets a check that its input is sorted
  bottom-up per file and refuses otherwise.
- Add `mruby-c-ext-helpers` to `mrbgem.rake`.
- Fix every declaration whose parameter name differs from its
  definition by copying the definition's name into the declaration.
  This is a text change with no semantic risk and it removes about a
  third of Part 3.1.
- Check: build, suite, smoke. Count of Part 2 unchanged except the
  dead lines.

### Step 2: the skeleton

- Write the headers of Part 4 as declarations only, under the RFC
  namespaces, in RFC order, with const arguments and return types.
  No bodies. No comments. Each declaration has a one-line
  `static_assert` or test name beside it where an RFC clause used to
  be a comment.
- Nothing is called yet. The tree builds as before.
- This step is the review point. The user reads the headers and says
  what is missing and what is too much. Open decisions 1 to 6 are
  settled here.

### Step 3: one walker

- `walk` in `webmachine.hpp` becomes the one walker with a
  "may this node call Ruby" bit. `run_engine`'s special cases become
  the callbacks of the nodes they special-case. `flow::answer`,
  `walk_compiled`, `lands_on`, `reaches_a_node_that_reads_the_request`
  and `block_skips_are_the_graphs` go. `shortcut_for` becomes the
  table fill of decision 2.
- Check: `test/wm_flow.rb` (the flow oracle), the bintests, the
  instruction count. This step is the one most likely to move the
  count. It is measured alone for that reason.

### Step 4: one Request, one Response

- `ReqFacts`, `ReqValues`, `ReqView` become `rfc9110::Request`, with
  offsets into the head buffer. `Held`, `rebase`, `follow_copy` and
  `kReqValueSpans` go.
- `RunState` splits into `WalkState`, `rfc9110::Response` and
  `SuspendedWalk`.
- The Ruby accessors keep their names in this step. Decision 1 is
  applied in step 8.
- Check: suite, smoke, count.

### Step 5: the pure functions under `rfc9110`, `rfc9111`, `rfc6265`, `rfc9457`

- Each function of Part 4.1, 4.2 and 4.6 moves under its namespace,
  in RFC order, with const arguments and a return value. Its comments
  are deleted as it moves; each fact goes to its destination of Part
  3.6 in the same commit.
- The second copies of Part 3.3 that these namespaces replace are
  deleted in the same step.
- The SWAR helpers are replaced by `std::string_view::find_first_of`
  and the count is read. If the count rises, the SWAR comes back as
  one function with a test, not a comment.
- Check: suite, smoke, count, and `grep -c '^\s*//'` on every moved
  file reads 0.

### Step 6: the connections

- `rfc9112::Connection` from the h1 parts of `http1*.cpp`.
- `rfc9113::Connection` from `http2.cpp` and `h2_wire.*`, on
  ls-hpack only. Decision 5 is measured here.
- `rfc6455::Connection` and `rfc7692::Codec` from `http1_wire.cpp`,
  `websocket.cpp`, `wsconn.cpp` and the ws parts of `http2.cpp`.
- `whatwg::EventStream` from `sse.cpp` and the sse parts of both.
- `Http1` (the class) is gone at the end of this step.
- Check: suite, `tools/conformance.sh` (h2spec, Autobahn), smoke,
  count.

### Step 7: the reactor

- `Ring<App>` splits into the nine classes of Part 4.9. The App
  contact surface becomes one declared interface: the list of
  `App::*` calls `ring.hpp` makes today, which is about forty.
- The four scope guards become one. `Conn` in `ring.hpp` splits along
  the groups already visible in it.
- Check: suite, `bintest/threads.rb`, `bintest/watcher.rb`,
  `bintest/zerocopy.rb`, smoke, count, and the sanitizer jobs.

### Step 8: the Resource and the Ruby surface

- The six parallel arrays and sixteen `ValueCb` fields become the two
  `Callback` arrays. `cb_mask` is derived, not stored.
- Decision 1 is applied. `docs/reference/request-and-response.md` and
  `docs/reference/resource.md` change in the same pull request.
- The three route tables become one `Router`.
- `request` is defined once.
- Check: suite, `bintest/resource.rb`, `bintest/application.rb`,
  `bintest/wmruby_app.rb`, smoke, count.

### Step 9: the last sweep

- Every remaining comment in the tree goes, the Rakefile and the build
  configs included. The Rakefile's regex over `reason()` and `kFaces`
  (used by `rake error_assets`) is replaced by a generated table, so
  no Ruby reads C++ source text.
- A CI gate: `grep -rE '^\s*(//|/\*)' src test bintest tools mrblib`
  must print nothing. Over the Ruby files, the Rakefile and the build
  configs, `grep -rE '^\s*#' | grep -v '^#!'` must print nothing. The
  gate runs in the suite job.
- `clang-format` over `src/` once, after the last move, so no earlier
  diff is a reformat.
- The 25 pages under `docs/` are read once more against the new
  names. `docs/explanation/reactor.md` and
  `docs/explanation/numbers-that-were-measured.md` are added.
  CLAUDE.md's claim about mruby-c-ext-helpers is made true (step 1)
  and its `Held::Span` paragraph is kept as history.
- Check: the whole of Part 2, measured again, in the pull request
  text.

## 7. What each step must not do

- No step changes what a client sees. The bintests are the contract.
  A step that needs a bintest changed names the RFC clause that says
  the old test was wrong.
- No step renames by text. A rename is clangd's position form,
  bottom-up, and the diff is read after.
- No step reformats a file it did not otherwise change.
- No step carries a session URL, a model name or a comment.
