# Cleanup plan

This plan says how the source of this tree becomes readable from its
declarations alone.

What was read for it: every file under `src/`, `mrblib/`, `test/`,
`bintest/` and `tools/`; `CLAUDE.md`; `bench/how-to-measure.md` and
the headers of `bench/threads.sh` and `bench/floor.sh`; the reference
pages under `docs/` and the three explanation pages; the tables of
contents of RFC 9110, 9111, 9112, 9113, 6455, 6265, 7541, 7692, 8441
and 9457. Not read in full: the other scripts under `bench/` and the
how-to pages under `docs/`. Step 0 reads them before the first
measurement. This plan makes no claim about speed.

The plan has seven parts. Part 1 states the rules. Part 2 gives the
numbers before the work. Part 3 states what the audit found. Part 4
states the target: the classes and the methods, in the order of the
RFCs. Part 5 records the decisions. Part 6 states the steps and the
loop that closes each step. Part 7 states what no step may do.

## 1. Rules

These rules add to CLAUDE.md. Where they meet, the stricter one holds.

1. **No comment in the source.** Not one line in `src/`, `mrblib/`,
   `test/`, `bintest/`, `tools/`, the Rakefile, the build configs or
   `mrbgem.rake`. A fact that a comment carried goes to one of four
   places: a name, a `static_assert` with a message, a test, or a page
   under `docs/`. Part 3.6 says which place takes which fact.
2. **A declaration says what happens.** The function name says what
   the function does. Each parameter name says what is passed. The
   return type says what comes back. A reader of the header alone
   knows the behaviour.
3. **Names come from the RFCs.** A field, a method, a status, a frame,
   an opcode and a close code carry the name the RFC gives them. The
   order of a class follows the order of the RFC that defines it. The
   order of its methods follows the section order. A name this tree
   invented for an RFC thing is replaced.
4. **No method hides anything.** No function wraps one library call.
   No function changes an argument unless its name says so. No
   function raises unless its name says so. No function does two
   things.
5. **Every argument is const.** A function reads its inputs and
   returns its result. There is no `out_value`, no `&sink` and no
   pointer that is written through. The return type is what the
   function makes. A function that changes an object is a method of
   that object.
6. **Use what a linked library has.** `std::`, mruby, liburing,
   ls-hpack, zlib, miniz, picohttpparser, simdutf and ada are in the
   build. Nothing they answer is written here a second time. Part 3.3
   lists every second copy this tree holds today.
7. **One Resource takes one Request and gives one Response.** There is
   one Request type and one Response type. Every field of either has
   the name the RFC gives it.
8. **An RFC that describes a procedure gives one method.** Where an
   RFC states steps, inputs and state for one thing, this tree has one
   function for it. Its arguments are the inputs the RFC names. Its
   state is the state the RFC names, passed in as a value. The pieces
   that are spread over the tree today are collected into that one
   function. Part 3.9 lists the procedures and where the pieces are.
9. **Every function could run in a functional language as it is.** A
   function takes values and returns a value. It reads no global. It
   writes no global. It keeps no static. State that changes is a value
   that goes in and a new value that comes out. An effect happens in
   one place, after a pure function decided it. An effect is a
   syscall, a ring submission or a Ruby call. CLAUDE.md's "decide,
   then do" is this rule. Part 3.8 lists the global state that breaks
   it today.
10. **The code is made as fast, as hard to attack and as plain as
    possible, by repeated testing and adjusting.** No step is done
    when it compiles. A step is done when the suite, the conformance
    runs, the sanitizers, the fuzzer and the instruction count have
    each run and none of them moved the wrong way. When one of them
    moves, the code is adjusted and they run again. The loop ends when
    a round changes nothing.
11. **Every larger change is measured before and after.** Before the
    change, the base commit is built and measured. After the change,
    the same tree with the change is built the same way and measured
    in the same session on the same machine. The arms alternate,
    A B A B A B, five runs each, and the medians are compared, as
    `bench/how-to-measure.md` says. Both numbers go into the pull
    request text with the row from `bench/results/`. A change too
    small for the clock is measured with `bench/instructions.sh`. A
    change with no before number is not merged. "Larger" means: the
    decision loop, a parser, a connection class, the reactor, HPACK,
    the send path, the body path, or anything a bench script names.
12. **Everything is written the way Kernighan and Ritchie wrote.** That
    is two things. First, the layout: a function's opening brace on
    its own line, every other brace on the line that opens its block,
    a space after a keyword, the star on the name. `.clang-format` in
    this tree states it already (`BreakBeforeBraces: Linux`). The C++
    Core Guidelines name it as NL.17. Second, the discipline: a
    function does one thing and fits on one screen. A name is short
    where its scope is short (`i`, `n`, `p`). A name says its purpose
    where its scope is long. The plain construct is chosen over the
    clever one. A loop is a loop and not a template. An interface is
    a few functions over a few types. Nothing is written for a reader
    who is not there. `clang-format` runs on every changed file before
    every commit. The suite job checks that it changes nothing.

### 1.1 Where a name comes from

A name in this tree is a word a reader knows from the HTTP code of a
large ecosystem, or from the C++ standard library. This tree invents
no verb.

The written source for C++ is the C++ Core Guidelines, section NL,
"Naming and layout". Its first rule is this plan's first rule: NL.1
"Don't say in comments what can be clearly stated in code." The rules
that decide a name: NL.5 "Avoid encoding type information in names",
NL.7 "Make the length of a name roughly proportional to the length of
its scope", NL.8 "Use a consistent naming style", NL.10 "Prefer
underscore_style names", NL.19 "Avoid names that are easily misread".
The Google C++ Style Guide adds two lines: "The most important rule:
names should describe purpose or intent", and "Function names should
generally be verb-like". The standard library is the third source.
Its verbs are `find`, `parse`, `format`, `from_chars`, `to_chars`,
`is_regular_file`, `contains` and `starts_with`.

What the HTTP libraries with the most users call things:

| verb | who uses it | for what |
|---|---|---|
| `parse_*` | Go `ParseTime`, `ParseHTTPVersion`, `ParseCookie`; Werkzeug `parse_date`, `parse_accept_header`, `parse_range_header`, `parse_etags`, `parse_cookie`; Rust `http` `HeaderValue::from_str`; Beast `request_parser` | bytes in, a value out |
| `format`, `dump_*`, `serialize`, `write` | Go `Header.Write`, `Request.Write`; Werkzeug `dump_header`, `dump_cookie`, `http_date`; Beast `serializer`; C++ `std::format` | a value in, bytes out |
| `get`, `set`, `add`, `del`, `values`, `has` | Go `Header.Get/Set/Add/Del/Values`; Java `getHeader/setHeader`; Express `req.get`, `res.set`; Rust `HeaderMap::get/insert/append/remove/contains_key` | one field of a field list |
| `is_*`, `has_*`, `*_matches` | Werkzeug `is_resource_modified`, `is_byte_range_valid`, `is_hop_by_hop_header`; Apache `ap_meets_conditions`; Rust `Method::is_safe`, `is_idempotent` | a yes or no |
| `handle`, `serve` | Go `ServeHTTP`, `ServeContent`, `ServeFile`; Java `doGet`, `service`; Erlang webmachine `handle_request`; nginx `*_handler` | the one entry that takes a request and gives a response |
| `decide`, `decision` | Erlang webmachine `webmachine_decision_core:decision/1`; Liberator `decide`; the webmachine diagram | one node of the graph |
| `read`, `write`, `send`, `receive` | Go `ReadRequest`, `io.Reader`, `io.Writer`; Beast `http::read`, `http::write`; Proxygen `sendHeaders`, `sendBody`, `sendEOM`; Envoy `decodeHeaders`, `encodeHeaders` | bytes across a connection |
| `encode`, `decode` | Envoy; ls-hpack `lshpack_enc_encode`, `lshpack_dec_decode`; Go `chunked` reader and writer | a wire coding |
| `redirect`, `error`, `not_found` | Go `Redirect`, `Error`, `NotFound`; Java `sendRedirect`, `sendError`; Flask `redirect`, `abort` | the named response shapes |
| `status_text`, `reason_phrase`, `canonical_reason` | Go `StatusText`; Rust `StatusCode::canonical_reason`; Rack `HTTP_STATUS_CODES` | the phrase of a status |
| `detect_content_type`, `sniff` | Go `DetectContentType`; the WHATWG standard's own word is "sniff" | the WHATWG table |
| `quote_etag`, `unquote_etag`, `generate_etag` | Werkzeug | the entity tag forms |
| `compile` | every regex library; Go `template.New().Parse()`; Rust `Regex::new` | turn a description into a table once |
| `suspend`, `resume` | C++ coroutines (`await_suspend`, `resume`); Kotlin; Python `asyncio` | stop a computation and continue it later |
| `precompute`, `cache` | everywhere | compute once, read many times |

The words this tree made up, and the word each becomes:

| today | becomes | why |
|---|---|---|
| `walk`, `run_engine`, `resource_run` | `handle_request` for the whole graph, `decide` for one node; the pure step is `next_decision` | Erlang webmachine and Go use these words |
| `fold`, `resource_fold`, `ws_fold`, `sse_fold` | `compile_resource` | a class becomes a table once; every regex library calls that compile |
| `park`, `parked`, `run_parkable` | `suspend`, `suspended`, `SuspendedRequest` | the language's own coroutine word |
| `lend`, `lent`, `unlend`, `LentBody`, `kLendFloor`, `zc_*`, `zero_copy_threshold`, `kZeroCopyDefault` | `send_body_without_copy_above`, `BodySentWithoutCopy`, `kSendBodyWithoutCopyAboveBytes` | the name says what happens and why. The body is sent from the Ruby string's own bytes through an `iovec`. The string is held until the send drains. The copy into the send buffer is the cost avoided. It is not zero copy: the tree has no `MSG_ZEROCOPY` and no `SEND_ZC`. The header of `bench/assets.sh` records that `SEND_ZC` was tried and refused. Decision 7 |
| `spell_*` (`spell_answer`, `spell_error`, `spell_fingerprint`, `spell_content_length`, `spell_steering`) | `format_*`, `serialize_*` | C++ `std::format`, Go `Write`, Werkzeug `dump` |
| `say_*`, `open_vm_or_say` | `print_*`, `report_*` | plain words |
| `bake`, `baked`, `has_baked` | `precomputed` | what it is |
| `konst`, `KonstSet`, `KonstAnswers`, `KonstValue` | `constant_*`, `PrecomputedAnswers` | English |
| `cats`, `Cat`, `disable_http_cats` | `error_page_images`, `disable_error_page_images` | what it is |
| `spill`, `BodySpill`, `spill_dir` | `body_file`, `BodyTemporaryFile`, `body_file_directory` | Go `os.CreateTemp`; the plain word |
| `sink`, `Sink`, `out_answer` | a return value; where a stream is real, `Writer` | Go `io.Writer`; under rule 5 most sinks become the return type |
| `carry`, `carry_` | `unparsed_bytes`, `leftover` | what it holds |
| `Held`, `Released`, `Seen`, `HeldList`, `Ender` | `ScopeGuard`, or `std::unique_ptr` with a deleter | the C++ idiom's name |
| `Took`, `Took::kOwed` | `HandleResult`, `awaiting_body` | a result, named as one |
| `Round`, `RunRound`, `round_at`, `RoundOut`, `spell_next_round` | `Request`, `WorkerAnswers`, `ResponseWriter`, `write_next_response` | "round" meant four things |
| `Bundle`, `Plan`, `Seg` | `PrecomputedRoute`; `SendPlan` stays, it is a plan of iovecs; `iovec` | what each holds |
| `tier` (asset tier, konst tier, run tier) | the word goes; each is a function named for what it answers | `serve_asset`, `answer_from_precomputed`, `handle_request` |
| `steering` | `request_line_summary` | what goes in the fingerprint |
| `word` in `word_has_zero_octet` | `uint64_t octets` | NL.19; "word" reads as a text word |
| `WM_UNREACHABLE` | `std::unreachable()` | C++23; until then the macro stays as the one macro in the tree |

The graph's own names stay: `B13`, `G7`, `service_available?`,
`resource_exists?`, `content_types_provided`. They are the diagram's
and webmachine-ruby's. An application author reads them in both.

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
| code paths that execute the decision graph | 5 (Part 3.4) |
| request structs | 3: `ReqFacts`, `ReqValues`, `ReqView` |
| log record structs | 5: `LogRec`, `ErrRec`, `AccessLine`, `ErrorLine`, `ErrFacts` |
| route tables per application | 3: http, websocket, sse |
| responsibilities in `Ring<App>` (`ring.hpp`, 2290 lines) | 17 |
| responsibilities in `Http1` (`http1.hpp`, 2117 lines) | 16 |
| responsibilities in `http2.cpp` (2808 lines) | 16 |
| file-scope and static mutable variables in `src/` | 41 (Part 3.8) |
| texts that build the application at boot | 2 (Part 3.11) |
| unfinished parts of the thread change | 7 (Part 3.12) |

Each number is measured again at the end of each step.

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

The five audit reports found the same in every file. The wrong words
are `count`, `sqe`, `round`, `conn`, `headers`, `bytes`, `field`,
`text`, `window`, `retry`, `stream_id`, `poll_tag`, `index`, `method`,
`answer`, `group`, `dynamic_body`, `block`, `one`, `other`,
`status_text`, `error_message`, `writer` and `prefix_variants`. Local
variables carry them too. `http1.cpp:1133` names a time
`status_text`. `http1_class.cpp:275` names a hex digit `dynamic_body`.
`http1.cpp:1862` names a route index `writer`.

`tools/rename-symbol.py` has a form that finds a symbol by the first
text match of its name in a file. In a 3000-line file the first match
is rarely the symbol meant. clangd then renames the wrong symbol, and
the result compiles. Step 1 deletes that form.

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

Some of them are the same shape twice. `H2WsAsk` and `H2SseAsk` have
the same seven fields. `Asked` and `NamedSym` are the same pair.
`ws::Frame` repeats four fields of `ws::Head`. `Resolved` and `Bound`
differ by one flag.

Under rule 5 most of these go. A function that returns its result
needs no `RunAnswer`, `BoundOut`, `WsAdmit`, `Negotiated`, `Parked`
or `Raised`. A function with three const arguments needs no pack. A
pack that survives is a real value and is named as one: `ByteRange`,
`MediaType`, `FieldLine`.

Other names that say nothing or say the wrong thing: `Held` (three
times, in `http1.hpp`, `ring.hpp` and `RunState::HeldTask`); `Round`
(two unrelated types, `Http1::Round` and `Conn::Round`); `Bundle`;
`konst`, `KonstSet`, `KonstAnswers`, `KonstValue`; `Conn::Slow`;
`ConnFailed` (an exception); `Released`, `Seen`, `HeldList` (four
scope guards for one job); `BootQueue` (it is the reactor's ring
too); `Method` in `wsconn.cpp` (a class and a symbol, where every
other file means an HTTP method); `Data` in `H2Stream` (a
destination, not data); `H2Control` (any frame); `RoundOut` (a
writer); `stream` in `Http1` (lowercase, and not a stream).

Words that are not English and not RFC: `fold` (compile a class into
a table), `park` (suspend a coroutine), `lend` (send without a copy),
`spell` (format), `say` (print), `konst` (constant), `bake` (compute
once at start), `cat` (an error page picture). Each gets the plain
word of Part 1.1.

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
| `hpack_length_spell`, `hpack_name_index_spell`, and the static-table indices written as bare numbers (`0x88`, `8`, `18`, `26`, `30`, `31`, `34`, `44`, `59`) in `h2_build_block`, `h2_build_asset_blocks`, `h2_build_asset_shared` and the 206 and 416 arms | measured piece by piece against ls-hpack (decision 5). What ls-hpack does exactly as well is deleted. What stays becomes one `hpack` namespace with the static table of Appendix A as a named enum, so `0x88` reads `encode_indexed(StaticTable::status_200)` |
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
| `accept_member_edge`, `accept_holds_media_type`, `accept_names_anything`, `accept_names_one_of_ours` | `choose_media_type`, which the same function calls already |
| `media_type_base`, `media_type_params`, `param_take_next`, `param_find_named`, `media_params_agree`, `media_type_pattern_matches`, `media_type_without_parameters` | one media type parser |
| `kFaces`, `status_title`, `status_source` | `reason(status)` |
| `access_log_method_name`, `kMethodName[]`, the switch in `request.cpp:77` | one method name table |
| `chunk_tchar` and `is_tchar`; OWS tested five ways | one `tchar` and one `ows` predicate |
| the private chunked-body decoder (`ChunkScan`, `chunk_lines_ok`, `chunk_size_line_ok`) beside `phr_decode_chunked` | `phr_decode_chunked` alone (decision 3) |
| `base64_encode_digest` | `simdutf::binary_to_base64` |
| `utf8_prefix_may_still_be_valid` | simdutf's `TOO_SHORT` count |
| `handler_call_with_no_args` and `handler_call_in_protected_call` | one trampoline with an argc |
| `exception_text`'s join loop | `mrb_ary_join` |
| `yield_array_entries` | `mrb_yield_argv` over `RARRAY_PTR` with the arena saved |
| about 90 `std::string_view(RSTRING_PTR(v), RSTRING_LEN(v))` sites and every `mrb_str_new(mrb, p, n)` return | mruby-c-ext-helpers. It is in the build, as CLAUDE.md says: mruby-cbor, mruby-chrono, mruby-lmdb, mruby-toml and four more gems depend on it. Nothing in `src/` includes it. `mrbgem.rake` does not name it. Step 1 names it, because a gem this tree calls directly is a direct dependency |
| `Config.check_whole_number` and `Config.check_text` in Ruby | the same bounds, checked again in `application.cpp` |
| hand pointer arithmetic | `std::string_view`, `std::span`, `std::distance`, `std::next`. Every C++ file breaks CLAUDE.md here |
| `passwd.cpp:106` and `webmachine-passwd/main.cpp:160`, two copies of the argon2 context fill | mruby-argon2, a declared dependency nothing uses |
| the LMDB layer in `passwd.cpp:66-230` and `webmachine-passwd/main.cpp:134` | mruby-lmdb, a declared dependency nothing uses |
| `text_of`, `flag_of`, `switch_of`, `number_of` in `webmachine-server/main.cpp` | the typed hash typedargs returned already |
| `setting_take_string`, `setting_take_int`, `section_take` in `config.cpp` | the hash mruby-toml returned already |
| three month name tables (`date_core`, `read_month_name`, logd `spell_ts`), two hex tables | one of each, or `std::format` |
| eleven argument bundles that exist because `mrb_protect_error` carries one `void *` (`OpenPack`, `AnswerThreadBoot`, `TomlAsk`, `SectionAsk`, `CrossAsk`, `BuildOne`, `JobBody`, `BlockRun`, `UnknownFlag`, `Tokens`, `Form`) | one lambda trampoline over `mrb_protect_error`, written once |
| six hand-written `mrb_gc_arena_save`/`restore` pairs in `compute_task.cpp` and `watcher.cpp` | `ArenaGuard`, which four other files use already |
| the spin wait on `ring_fd` (`server.cpp:486`) | `std::condition_variable`, which `ComputePool` uses for the same question |
| `WM_HANDOVER_SEND`/`TAKE`, `slots_lock` and atomics on one handover | one ordering mechanism |
| three copies of "open a VM and report a gem init raise" (`main.cpp:562`, `open_vm_or_say`, `server.cpp:446`) | one |
| three copies of "get an sqe, submit when full, retry once" (`sqe_or_raise`, `watcher_free`, `compute_task.cpp:948`) | one |

### 3.4 Five executions of one graph

The decision graph is one table, `kFlow`. Five pieces of code execute
it:

1. `flow::walk` (`webmachine.hpp:489`): constants only, no Ruby.
2. `flow::answer` (`webmachine.hpp:600`): the shortcut in front of 1.
3. `run_engine` (`resource.cpp:1486`): with Ruby, with suspend and
   resume. Its fall-through tail repeats the loop body of 1.
4. `walk_compiled` and `status_reached_from` (`webmachine.hpp:608`):
   a template unrolling. Its only callers are five `static_assert`s
   that repeat five earlier `static_assert`s.
5. `lands_on`, `reaches_a_node_that_reads_the_request`,
   `shortcut_for`, `block_skips_are_the_graphs`: each has its own copy
   of the test `kind == kRequest || node == kC4`.

One `next_decision` and one `handle_request` serve. The speed of the
constant path does not come from a second execution. It comes from a
status that was computed once, at route time, for the plain request
of each method. That table stays. The same `next_decision` fills it
at route time.

### 3.5 One request under three names, and the Ruby surface

`ReqFacts` holds the booleans the graph reads. `ReqValues` holds
pointers to the field values. `ReqView` holds the target, the method
and the content. All three describe one request. One `Request` holds
all of it, as offsets into the one head buffer. Then nothing is
rebased when the buffer moves.

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
websocket and sse resources define no method from C. Their callback
names are found by search at compile time.

Every name that is webmachine-ruby's stays (decision 1). What is
reachable twice stays reachable twice. What changes: each name is
defined once, over one `http::Request`.

### 3.6 Where the facts in the comments go

3756 comment lines were read. They hold four kinds of fact. Each kind
has one destination.

| kind | example | destination |
|---|---|---|
| an RFC clause | `// RFC 9110 13.1.3: a date in the future is ignored (l15)` | the function name, for example `http::if_modified_since_in_the_future_is_ignored`, and a test whose name cites the clause |
| a measured number | `kLendFloor = 4096`, the `sendmsg` cost, the 128 KiB default | `bench/results/` holds the row already; `docs/explanation/` gets one page, `numbers-that-were-measured.md`, that lists each constant, its value, the row it came from and the script that moves it |
| a kernel or library fact | `EINTR` on `close(2)`, io-wq affinity, `MSG_RING` between rings, `mrb_noreturn` under `-std=c++20`, `MRB_FUNCALL_ARGC_MAX` | a name (`close_ignoring_eintr`); a `static_assert` where it is a constant; `docs/explanation/reactor.md` where it is a design fact |
| a bug that was fixed | `// A guard that returns instead of raising hides our own bug` | a test in `test/` or `bintest/` that fails when the bug returns |

A comment that is none of the four is deleted with nothing kept. Most
comments are of that kind. They restate the code below them.

Two comments are false today. `wsconn.cpp:884` names `take_pending`,
which no longer exists. `wsconn.cpp:272` describes an arity check that
the next comment says does not happen. Two comments each claim to be
the only writer of a field line (`resource.cpp:598`,
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
`#include <simdutf.h>` in `test/wm_ruby.cpp`; `watcher_slot`,
`watcher_source_of`, `watcher_block_of`, `close_or_throw`.

`tools/comment-anchors.sh` and its baseline: nothing runs it. Its
baseline is in a format its own reader cannot parse. After this plan
it measures an empty set.

### 3.8 Global state

Rule 9 forbids these. Each is a value some function reads without
taking it as an argument:

| where | what |
|---|---|
| `server.cpp:35-166` | `opts_`, `main_inputs_`, `assets_up_`, `log_fd_`, `err_fd_`, `assets_`, `error_assets_`, `error_assets_up_`, `error_assets_note_`, `mime_`, `http_`, `ring_`, `built_`, `entered_`, `answer_threads_`, `answer_ring_fds_` |
| `application.cpp:34-35` | `registries_lock_`, `registries_` (a map from VM to registry) |
| `docroot.cpp:28-102` | `docroot_path_`, `docroot_fd_`, `spill_dir_`, `body_file_slots_` |
| `request.cpp:33-44` | `disp_override_`, `disp_override_set_`, `body_io_` |
| `compute_task.cpp:147-593` | `reg`, `builds_closed_`, `value`, `pool_lock_`, the one `ComputePool` |
| `resource.cpp:83` | `thrown`, the process-wide native method table |
| `passwd.cpp:72` | `lock` |
| `wsconn.cpp:309` | `scratch`, a static string reused across connections |
| `http1_class.cpp:62` | `turn`, a static counter that rotates `Retry-After` |
| `ring.hpp:1810` | `warned` |
| `webmachine.hpp:1157` | `app_build_hash()`, a function that returns a reference to a static |
| `request.cpp`, `response.cpp` | `request_bind`, `response_bind`: the current request and resource are set into file scope before a callback and read from there inside it |

The last row is the widest one. Every Ruby accessor of `request` and
`response` reads the request from a file-scope pointer. The caller
set that pointer a moment before. Under rule 9 the request is a value
the Ruby object holds. The accessor reads it from `self`.

Server-wide state that must exist once becomes one `Server` value.
That is the ring, the assets map, the error pages, the mime table and
the docroot descriptor. `main` builds it and passes it down. A worker
VM gets a `Worker` value the same way. No function reads a global.

### 3.9 Procedures the RFCs give, and where their pieces are

Rule 8 applied to what the tree does today. Each row is one method in
the skeleton. The right column is what the method collects.

| RFC and section | the one method | the pieces today |
|---|---|---|
| 9110 13.2, evaluation of preconditions: the six ordered steps over If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since, If-Range | `http::evaluate_preconditions(fields, validators, method) -> optional<status>` | `header_switch` (`webmachine.hpp:1763`), `eval_request` cases G8 to L17, `kFlow` rows G8 to L17, `run_engine`'s G11/K13/H12/L17 arms (`resource.cpp:1486`), `etag_list_match`, `star_value`, `parse_http_date`, `if_range_matches` |
| 9110 12.5.1, Accept: media ranges, q-values, specificity, ties | `http::choose_media_type(offered, accept) -> optional<index>` | `choose_media_type`, `accept_is_exact`, the second parser in `error_assets.cpp:392-474`, the third in `resource.cpp:472-1278`, `sniff::media_type_without_parameters` |
| 9110 12.5.3, Accept-Encoding: identity, `*`, q=0 | `http::choose_content_coding(accept_encoding) -> Coding` | `gzip_acceptable`, `answer_step`'s `gzip_ok`, `compressible_media_type` |
| 9110 14.2 and 14.1.2, Range and byte ranges: the satisfiable test, the last-byte-pos clamp, the 416 | `http::select_byte_range(range, if_range, etag, complete_length) -> RangeDecision` | `parse_range`, `read_size`, `if_range_matches`, `asset_step`, `RangeAsk`, the 206 and 416 arms in `http1.cpp:698` and `http2.cpp:1163` |
| 9110 8.8.3.2, entity tag comparison, strong and weak | `http::entity_tag_matches(tag, list, comparison)` | `etag_list_match`, `EtagMatch`, `star_value` |
| 9110 5.6.7, HTTP-date: three formats in, IMF-fixdate out | `parse_http_date`, `format_imf_fixdate` | `parse_http_date`, `read_fixed_digits`, `read_month_name`, `epoch_from_civil`, `Civil`, `date_core`, `write_two_digits`, `mtime_spell_imf_date`, `patch_date`, `head_patch_date`, `Listing.stamp` |
| 9110 10.2.2 and 3986 5.3, Location and reference resolution | `http::resolve_location(base, reference)` | `uri_join`, `UriRef`, `base_uri`, the `create_path` join in `run_node_n11` |
| 9110 6.1 and 9112 6.3, message body length: the seven ordered rules | `http1::message_body_length(request_fields) -> BodyLength` | `WireFacts`, `transfer_encoding_fold`, `connection_field_holds_token`, `head_framing_status`, `parse_content_length`, `body_take_status` |
| 9112 7.1.3, decoding chunked | `phr_decode_chunked`, called from `http1::Connection`, nothing of ours (decision 3) | `take_chunked`, `ChunkScan`, `chunk_lines_ok`, `chunk_size_line_ok`, `chunk_tchar`, `chunk_hex`, `hex_digit` |
| 9112 9.3, persistence: the version, the Connection field, the close | `http1::connection_persists(version, request_fields, response_fields)` | `WireFacts::conn_close`, `persist`, `Variants` (three copies of every head for three Connection lines), `ConnectionOption` |
| 9112 2.1 and 9110 6.1, serialize a response head | `http1::serialize_head(status, fields) -> string` | `head_spell`, `SpelledHead`, `answer_assemble`, `assemble_dynamic`, `build_one_variant`, `build_open_prefix`, `file_spell`, `spell_error`, `run_append_field`, `header_append_key_value` |
| 9113 4.1, frame header in and out | `http2::parse_frame_header`, `serialize_frame_header` | `H2FrameHead`, `h2_u32`, `h2_u24`, `h2_u16`, `u32_put`, `control_frame_emit`, `H2Control` |
| 9113 8.3.1 and 8.2.1, request pseudo-headers and field validity | `http2::validate_request_fields(decoded) -> Request or ErrorCode` | the loop in `h2_dispatch` (`http2.cpp:640-1095`), `h2_field_ok`, `h2_path_ok`, `h2_word_is_path`, `h2_wire_header_ok`, `h2_trailer_name_ok`, `kH2NameOctet` |
| 9113 5.2 and 6.9, flow control: two windows, WINDOW_UPDATE, the 2^31-1 bound | `http2::apply_window_update(state, increment) -> state or ErrorCode`, `sendable(state, wanted) -> size` | `h2_credit_connection`, `h2_send_step`, `stream`, `h2_advance`, `flow_window`, the arms at `http2.cpp:1844-2022, 2770-2792` |
| 9113 5.1, stream states | `http2::Stream::transition(event) -> Stream or ErrorCode` | `H2State::open`, `close_stream`, `h2_is_idle`, `h2_reset_stream`, the state checks spread through `h2_feed` |
| 7541 5.1, 6.1, 6.2 and Appendix A, HPACK encoding | `hpack::encode_integer(value, prefix_bits)`, `encode_indexed(StaticTable)`, `encode_literal_with_name_index(StaticTable, value)`, `encode_literal(name, value)`; each is kept only where ls-hpack is not as good (decision 5); decoding stays ls-hpack | `hpack_length_spell`, `hpack_name_index_spell`, the block builders, the bare indices, `h2_enc_field`, `H2BlockOut`, `H2State::enc_ins`, the head cache |
| 6455 4.2.2, the server opening handshake: the eight checks and the response | `websocket::open_handshake(request) -> Response or status` | `ws_upgrade`, `ws_admit`, `WsAdmit`, `accept_key_compute`, `base64_encode_digest`, `ws_version`, `h2_extended_connect`, `H2Connect`, `websocket::permessage_deflate::negotiate` |
| 6455 5.2 to 5.6, framing: header, masking, fragmentation, control frames | `websocket::parse_frame(state, bytes) -> (state, frames, consumed)`, `serialize_frame(frame)` | `read_head`, `header_need`, `header_build`, `unmask_copy`, `ws::Head`, `ws::Frame`, `ws::Mask`, `ws::Message`, `admit`, `frame_begin`, `data_frame_emit`, `message_deliver`, `utf8_prefix_may_still_be_valid` |
| 6455 7, closing: code, reason, the handshake, the abnormal cases | `websocket::close(state, code, reason) -> (state, frame)` | `close_payload_build`, `close_read`, `ws::Close`, `close_code_of_symbol`, `ws_going_away`, `stream_report_close` |
| 7692 7.1 and 7.2, permessage-deflate parameters and payload transform | `websocket::permessage_deflate::negotiate`, `Codec::compress`, `Codec::decompress` | `wsdeflate::negotiate`, `Negotiated`, `window_bits`, `Params`, `Codec` |
| 6265 4.1 and 4.2, Set-Cookie out and Cookie in | `cookies::serialize_set_cookie(name, value, attributes)`, `parse_cookie(field)` | `response_set_cookie`, `CookieAttribute`, `CookieRules`, `cookie_rules_read`, `cookie_rules_check`, `cookie_same_site_name`, `request_get_cookies`, `cookie_repeats` |
| 9457 3.1, the problem details object | `problem_details::ProblemDetails` and its JSON | `ErrorResource.problem_document` in `mrblib/webmachine.rb` |
| 9110 11.6.2, Authorization: scheme and credentials | `http::parse_authorization(field) -> (scheme, credentials)` | `request_get_authorization`, `spell_steering`'s scheme cut, `passwd.cpp`'s decode |
| 9110 15 and 10.2.1, the status line and Allow | `reason_phrase(status)`, `allow_field_value(methods)` | `reason`, `kFaces`, `status_title`, `status_source`, `run_append_allow`, `H2BlockFields::allow`, `kAllow` |

Every row also names an interface of the functional shape. A
connection is a value. The bytes are a value. The result is a new
connection value and what to send. The ring then sends it. That is
the only place a send happens.

### 3.10 Files that hold more than one thing

- `http1_wire.cpp` holds only WebSocket code.
- `http1_members.cpp` holds the body file and the h2 connection
  state.
- `http2.cpp` holds `Http1::pending` and `Http1::spell_next_round`,
  which carry the h1 paths.
- `ring_setup.hpp` holds rlimit code, ring setup and the operation
  tag enums. The enums belong with `Op`.
- `webmachine.hpp` (2842 lines) holds the graph, the router, the
  logger, the passwd record, the http helpers, the request, the
  resource, the compute pool, the watcher, gzip, mime, assets, error
  pages, the application spec, sniff, docroot, server options and
  config. One change recompiles the tree.

### 3.11 The boot is written twice, and one flag is inverted

`server.cpp` builds the application twice, in two texts that must
agree. One text is for the acceptor (`server.cpp:652-694`). The other
runs once per answering thread (`answer_thread_boot`,
`server.cpp:366-385`). Both call `app_load`, `app_registered_all`,
`app_inputs_build`, `new Http1`, `serve_docroot`, `open_error_assets`
and the two thresholds. With `--threads=N` an application's `ready`
hook runs N times. `conf.url` is written N times.

Other things stated more than once: the "first application that
names one decides" loop, six times in one function; the config search
path, three times; the stop signal mask, twice; the privacy words,
four times.

The four privacy statements do not agree. That is a bug in the
shipped binary. `docs/how-to/logs.md:28`,
`docs/reference/configuration.md:209`,
`docs/reference/command-line.md:159` and the generated config file
(`config.cpp:204`) all say the same: `full` keeps the address, `anon`
drops the host part, `none` writes no address. `webmachine-logd`
(`tools/webmachine-logd/main.cpp:169-204`) does the reverse. `full`
writes `-`. `none` writes the whole address. The DNT promotion turns
`none` into `anon`. The warning in `server.cpp:622` follows the
daemon, not the documentation. An operator who writes
`privacy = "none"` to log no address logs every address in full. The
documentation is the contract. Step 1 fixes the daemon, with a
bintest that reads one line at each level.

Name collisions across files: `Registry` means three things
(`application.cpp:30`, `compute_task.cpp:134`,
`Webmachine::Workers::Registry`). `Setting` means two
(`application.cpp:90`, `config.cpp:64`). `Slot` in
`compute_task.cpp:74` is a job. Its fields `out_ask` (the answer),
`deadline` (a duration) and `started` (a tag) say the wrong thing.
`registry_of_this_vm` returns a process-wide static.

The threads as they are today, so that the `Server` and `Worker`
values of Part 3.8 are cut along the real crossings:

| thread | owns | talks through |
|---|---|---|
| the acceptor | the listeners, one VM, one ring | `MSG_RING` to the answering threads and the compute workers |
| answering threads (`--threads`) | one VM, one ring, one `Http1` each | `MSG_RING` in; a spin on `ring_fd` at boot |
| compute workers | one VM, one ring each | `MSG_RING` both ways; a separate control ring for stop |
| `webmachine-logd`, two processes | a socketpair | `LogRec` and `ErrRec`, a fixed header then the bytes |

### 3.12 The unfinished change on `reactor`

This branch is cut from `reactor`. `reactor` is in the middle of one
change: answering from several threads. The acceptor takes every peer
and hands it to a thread's ring with `MSG_RING`
(`ring.hpp:1017-1094`). Each thread has its own VM, its own `Http1`
and its own ring (`server.cpp:353-520`). The boot ring became
`BootQueue` (commit 52ff900). The connection table became
`RLIMIT_NOFILE` (commits 5a8b1ec, 4f77226). The last two days of
history are this change and its measurements. Two commit titles say
that numbers were wrong. This plan makes no statement about those
numbers.

The parts of the change that are not finished:

- `RingConfig::rings_in_process` is written (`server.cpp:703`) and
  read nowhere.
- `boot_queue_down` has no caller.
- Commit 8767d0e replaced a hash of the peer's pid or address (murmur3,
  commit de25166) with one turn per thread, `place_of_next_peer`.
  `docs/reference/command-line.md:30` still says the thread is the
  one "its address or its pid names". The test that commit de25166
  names, `test/wm_spread.rb`, is not in the tree.
- `bench/floor.sh:518` writes "(one ring, one thread)" on every
  harness row, with `threads=2` on the same row.
- `docs/explanation/one-thread.md:9` says "one process and one
  thread". CLAUDE.md names this sentence as the one a thread flag
  makes false.
- With `--threads=N` an application's `ready` hook runs N times and
  `conf.url` is written N times (Part 3.11).
- The answering threads start with a spin on `ring_fd`.
- TLS is a second unfinished change, older than the threads. The
  record layer left with mruby-ktls. mruby-tls is not in the tree.
  `listener_tls_refuse` (`server.cpp:244`) stops a server whose
  application asks for TLS. `AppSpec` still parses `cert_path`,
  `key_path`, `named_pairs` and `tls`. The `kTls*` operation kinds in
  `ring_setup.hpp:149` are unused. `docs/how-to/tls.md` describes a
  setup the binary refuses.

These are facts about the tree. They are recorded so that no cleanup
step mistakes one of them for its own bug. Neither the thread change
nor the TLS change is this plan's work (decision 8). The plan names
only the dead code of both (Part 3.7) and the pages that no longer
say what the binary does.

## 4. The target, in the order of the RFCs

Namespaces are named by content (decision 4): `http` for RFC 9110
and 9111, `http1` for RFC 9112, `http2` for RFC 9113, `hpack` for RFC
7541, `websocket` for RFC 6455, 7692 and 8441, `cookies` for RFC 6265,
`problem_details` for RFC 9457, `sse` and `sniff` for the WHATWG
standards, `webmachine` for the graph and the Resource. A file is
named for what is in it. Inside a namespace the declarations follow
the order of the RFC's sections. A reader with the RFC open finds the
code in the same place. The section number is in the test names and
the `static_assert` messages. The headings below keep the RFC number
so that this document can be read beside the RFC.

Every function below takes const arguments and returns its result.
Every name below is a proposal for the skeleton commit (step 2). The
skeleton is reviewed before code moves under it.

### 4.1 `http`: RFC 9110, HTTP Semantics

```
namespace http {

struct FieldLine { std::string_view name; std::string_view value; };
class Fields {
  std::optional<std::string_view> first(std::string_view name) const;
  std::string combined(std::string_view name) const;
  std::vector<std::string_view> all(std::string_view name) const;
  Fields with(FieldLine line) const;
  Fields without(std::string_view name) const;
};
bool field_name_is_token(std::string_view name);
bool field_value_has_no_cr_lf_nul(std::string_view value);
bool token_equals_ignoring_case(std::string_view a, std::string_view b);
std::optional<std::chrono::sys_seconds> parse_http_date(std::string_view text);
std::string format_imf_fixdate(std::chrono::sys_seconds at);

enum class Method { GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, other };
struct Request {
  Method method;
  std::string_view method_token;
  std::string_view target;
  std::string_view path;
  std::string_view query;
  Fields fields;
  Content content;
  bool tls;

  std::string_view host() const;

  std::optional<std::string_view> authorization() const;
  std::optional<std::string_view> accept() const;
  ...
};
struct Response {
  uint16_t status;
  Fields fields;
  Body body;
};

std::string content_type_with_charset(std::string_view media_type);
bool media_type_is_compressible(std::string_view media_type);
std::optional<std::string> gzip(std::string_view bytes);
std::optional<size_t> parse_content_length(std::string_view value);
enum class Validator { strong, weak };
bool entity_tag_matches(std::string_view tag, std::string_view list, Validator how);
std::string quote_entity_tag(std::string_view raw);

std::string allow_field_value(std::span<const Method> allowed);
std::string resolve_location(std::string_view base, std::string_view reference);

std::optional<size_t> choose_media_type(std::span<const std::string> offered, std::string_view accept);
bool gzip_is_acceptable(std::string_view accept_encoding);
std::string vary_field_value(...);

struct Preconditions { ... the five fields, parsed };
std::optional<uint16_t> evaluate_preconditions(const Preconditions &p, const Validators &v, Method m);

struct ByteRange { size_t first; size_t last; };
enum class RangeResult { none, one, unsatisfiable };
std::pair<RangeResult, ByteRange> parse_byte_range(std::string_view range, size_t complete_length);
bool if_range_matches(std::string_view if_range, std::string_view etag);

std::string_view reason_phrase(uint16_t status);
}
```

What moves here: `tok_eq`, `star_value`, `path_only`, `parse_method`,
`with_charset`, `compressible_media_type`, `reason`, `date_core`,
`spell_content_length`, `parse_content_length`, `NamedFieldIndex`,
`header_switch`, `parse_range`, `if_range_matches`,
`gzip_acceptable`, `etag_list_match`, `parse_http_date`,
`choose_media_type`, `accept_is_exact`, `etag_spell`, `uri_join`,
`field_name_is_the_servers`, `field_name_ok`, `field_value_ok`,
`join_repeated_fields`, `gzip::compress`; from `resource.cpp` the
media type parser and `run_append_allow`.

What goes: everything in Part 3.3 that this namespace replaces;
`ReqFacts`, `ReqValues`, `ReqView`, `kReqValueSpans`, `rebase`,
`follow_copy`, `Held`. The SWAR helpers (`word_has_zero_octet` and
the others) stay until step 5 measures `std::string_view` against
them under rule 11. The measurement decides.

### 4.2 `http`: RFC 9111, Caching

```
namespace http {
bool freshness_is_stated(const http::Fields &response_fields);
constexpr std::string_view no_cache_directive = "no-cache";
bool target_names_a_directory(std::string_view target);
}
```

### 4.3 `http1`: RFC 9112, HTTP/1.1

```
namespace http1 {
class Connection {

  ParseResult parse_head(std::string_view bytes) const;

  BodyLength body_length(const http::Request &r) const;

  ChunkedResult decode_chunked(std::string_view bytes) const;

  bool persists(const http::Request &r) const;
  std::string serialize(const http::Response &r, Persistence p) const;
};
}
```

What moves here from `http1.cpp`, `http1_class.cpp` and `http1.hpp`:
the head loop of `feed_parse`, `wire_header_read`,
`transfer_encoding_fold`, `connection_field_holds_token`,
`head_framing_status`, `WireFacts`, `take_body`, `take_chunked`,
`BodySpill`, `head_spell`, `answer_assemble`, `assemble_dynamic`, the
`build_*` functions of the prebuilt store, `patch_date`, `Preface`,
`h1_preface`, `h1_upgrade_or_stream`.

What does not belong to HTTP/1.1 moves elsewhere: the docroot file
transfer (`FileXfer`, `FileStep`, sixteen `file_*` methods), the
asset answers, the coroutine suspend and resume, the compute and
watcher bridges, the send plan, the error pages, sniffing. Each goes
to its own class in Part 4.9.

### 4.4 `http2` and `hpack`: RFC 9113 and RFC 7541

```
namespace http2 {
enum class FrameType : uint8_t { DATA = 0x0, HEADERS = 0x1, ... CONTINUATION = 0x9 };
enum class ErrorCode : uint32_t { NO_ERROR = 0x0, PROTOCOL_ERROR = 0x1, ... };
enum class Setting : uint16_t { HEADER_TABLE_SIZE = 0x1, ... };
struct FrameHeader { uint32_t length; FrameType type; uint8_t flags; uint32_t stream_id; };
FrameHeader parse_frame_header(std::span<const unsigned char, 9> octets);
std::array<unsigned char, 9> serialize_frame_header(FrameHeader h);

class Stream {
  State state; int64_t send_window; int64_t receive_window; ...
};
class Connection {

  ...
};
}
```

HPACK encoding was written here for speed. Decision 5: it stays only
where ls-hpack has nothing as good. In step 6 each piece is measured
against its ls-hpack form under rule 11. The pieces are the
static-table heads, the integer coding and the head cache. Equal or
better means ls-hpack. What stays ours becomes one `hpack` namespace
in the order of the RFC: 5.1 integer representation, 6.1 indexed
field, 6.2 literal field with and without a name index, and the
static table of Appendix A as an enum. The enum is
`enum class StaticTable : uint8_t { authority = 1, method_GET = 2,
... status_200 = 8, ... content_type = 31, ... }`. A reader then sees
`encode_indexed(StaticTable::status_200)` where `0x88` stood.
Decoding stays ls-hpack. A decoder must handle every input, and a
decoder of our own is a second parser to fuzz.

What moves out: WebSocket over h2 (RFC 8441) to 4.5, SSE over h2 to
4.7, the h1 paths in `spell_next_round` to 4.3.

### 4.5 `websocket`: RFC 6455, RFC 7692 and RFC 8441

```
namespace websocket {
std::array<char, 28> sec_websocket_accept(std::string_view sec_websocket_key);
enum class Opcode : uint8_t { continuation = 0x0, text = 0x1, binary = 0x2, close = 0x8, ping = 0x9, pong = 0xA };
struct FrameHeader { bool fin; bool rsv1; Opcode opcode; bool masked; uint64_t payload_length; std::array<unsigned char,4> masking_key; };
std::optional<FrameHeader> parse_frame_header(std::span<const unsigned char> octets);
size_t serialize_frame_header(FrameHeader h, std::span<unsigned char, 14> out);
std::string unmask(std::string_view payload, std::array<unsigned char,4> key, size_t offset);
enum class CloseCode : uint16_t { normal_closure = 1000, going_away = 1001, protocol_error = 1002, ... };
struct Close { CloseCode code; std::string_view reason; };
class Connection { ... };
}
namespace websocket::permessage_deflate {
struct Parameters { bool server_no_context_takeover; bool client_no_context_takeover; uint8_t server_max_window_bits; uint8_t client_max_window_bits; };
std::optional<Parameters> negotiate(std::string_view sec_websocket_extensions);
class Codec { ... };
}
```

`ws::Head` and `ws::Frame` become one `FrameHeader`. `ws::Message`
becomes the reassembly state of `Connection`. `WsAdmit` and
`Negotiated` go under rule 5.

### 4.6 `cookies` and `problem_details`: RFC 6265 and RFC 9457

```
namespace cookies {
std::vector<std::pair<std::string_view, std::string_view>> parse_cookie(std::string_view cookie_field);
std::string set_cookie_field_value(std::string_view name, std::string_view value, const Attributes &a);
}
namespace problem_details {
struct ProblemDetails { std::string type; uint16_t status; std::string title; std::string detail; std::string instance; };
}
```

### 4.7 `sse` and `sniff`: WHATWG Server-Sent Events and MIME Sniffing

```
namespace sse {
class EventStream { std::string event(std::string_view name, std::string_view data) const; std::string comment_line() const; ... };
}
namespace sniff {
enum class Verdict { agrees, contradicts, unknown };
Verdict sniff(std::string_view declared_media_type, std::string_view first_octets);
constexpr size_t octets = 512;
}
```

### 4.8 `webmachine`: the decision graph and the Resource

```
namespace webmachine {
enum class Node : uint8_t { B13, B12, ... P11 };
struct Edge { Node node; Kind kind; std::string_view callback; Target on_true; Target on_false; };
inline constexpr Edge graph[] = { ... };

struct Callback { mrb_sym name; mrb_method_t method; bool is_irep; NativeCallback native; bool on_class; uint8_t argc; };
struct Resource {
  std::array<Callback, node_count> node_callback;
  std::array<Callback, value_count> value_callback;
  std::array<uint16_t, method_count> plain_request_status;
  ...
};
Resource compile_resource(mrb_state *mrb, mrb_value klass);
struct Decision { Node at; std::optional<Callback> ask; std::optional<uint16_t> status; };
Decision next_decision(const Resource &r, const http::Request &q, const DecisionState &state);
http::Response handle_request(const Resource &r, const http::Request &q);
}
```

The `clause` string of `kFlow` is read by nothing. It goes. Each
clause becomes the name of that edge's case in `test/wm_flow.rb`.

`RunState` (60 fields) splits three ways: what the decision loop
carries (`DecisionState`), what the response holds
(`http::Response`), and what is suspended (`SuspendedRequest`: the
coroutine handle and its pending jobs). Nothing else of it survives.

### 4.9 Not in an RFC: the server

These are the parts of the tree no RFC describes. Each is one class
with one job. The list follows the boot order.

| class | job | comes from |
|---|---|---|
| `Invocation` | what the command line and the config file decided, merged once; absence stays visible | `config.cpp`, `ServerOptions`, `Config`, `AppSpec` settings, `Invocation` in `main.cpp` |
| `boot(const Invocation &, mrb_state *) -> Server` | the one boot: load the app, build the router, open the pack, the docroot and the pages. The acceptor and every answering thread call the same function once. The `ready` hook runs once | `server_run`, `server_build_ring_config`, `answer_thread_boot`, `app_inputs_build` |
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

## 5. Decided

These questions were open. They were decided on 2026-09-19.

1. **The names of webmachine.** This tree is a port of webmachine: the
   Erlang original and webmachine-ruby. Every name of webmachine-ruby's
   `Request` and `Response` stays: `method`, `uri`, `headers`, `body`,
   `routing_tokens`, `base_uri`, `disp_path`, `path_info`,
   `path_tokens`, `[]`, `has_body?`, `query`, `cookies`, `https?`,
   `get?`, `head?`, `post?`, `put?`, `delete?`, `trace?`, `connect?`,
   `options?`; `headers`, `code`, `body`, `redirect`, `trace`, `error`,
   `do_redirect`, `set_cookie`, `is_redirect?`, `redirect_to`. The RFC
   field accessors this tree added stay beside them. Nothing an
   application can see is removed. What the port lacks today
   (`routing_tokens`, `[]`, `https?`, `trace?`, `connect?`,
   `response.trace`) is a gap of the port. This plan names the gap and
   does not fill it. `response.userdata` is this tree's own. It stays
   until its owner says otherwise.
2. **The precomputed plain-request status.** Stays, as a table
   `next_decision` fills at route time. Measured before and after.
3. **picohttpparser.** Everything picohttpparser offers is used.
   Anything this tree wrote again that picohttpparser has is deleted.
   `phr_decode_chunked` stays. The private chunked grammar
   (`ChunkScan`, `chunk_lines_ok`, `chunk_size_line_ok`, `chunk_tchar`,
   `chunk_hex`) goes. The same rule holds for every linked library
   (Part 3.3).
4. **Namespaces by content, not by RFC number.** `http`, `http1`,
   `http2`, `hpack`, `websocket`, `sse`, `sniff`, `cookies`,
   `problem_details`, `webmachine`. The RFC section is in test names
   and `static_assert` messages. The order inside a namespace is the
   RFC's section order.
5. **HPACK.** The hand-built encoder stays only where ls-hpack has
   nothing as good. Each piece is measured under rule 11 against the
   ls-hpack form: the static-table heads, the integer coding, the head
   cache. Equal or better means ls-hpack. Decoding is ls-hpack already.
6. **The callback names of webmachine.** They stay. Same reason as 1.
7. **The threshold that was called `zero_copy_threshold`.** The name
   says what happens and why. What happens: above N bytes the server
   sends the body from the Ruby string's own memory instead of copying
   it into the send buffer. Why: the copy is the cost it avoids, in cpu
   per send and in memory per slow reader. The old comment recorded 300
   stalled readers of a 64 KB answer holding 19.5 MB of duplicates. The
   name is `send_body_without_copy_above`: the flag
   `--send-body-without-copy-above=N`, the TOML key and the `conf.*`
   setter the same, the constant `kSendBodyWithoutCopyAboveBytes`, the
   type `BodySentWithoutCopy`. The old flag and key are read for one
   release with a warning that names the new one. Another word order is
   one rename at the review of step 2.
8. **The thread change on `reactor`.** Not touched. Nobody asked for it
   to change. Step 0 takes the baseline on the tree as it is. Part 3.12
   stays as a record of facts, not as work of this plan.

## 6. Steps

Each step is one pull request. Each step ends with the check named
under it. The suite (`rake test`) and the ship smoke
(`rake ship_smoke`) run in CI for every step. Nothing may fail. The
instruction count (`bench/instructions.sh`) runs at the end of each
step and is compared to step 0. A step that raises it by more than
one percent is discussed before merge.

Rule 10 makes every step a loop. The loop is the same each time:

1. Write the change.
2. `tools/syntax-check.sh` on the touched files, then
   `clang-format -i` on them.
3. `rake test`. Nothing may fail.
4. `tools/conformance.sh` when a connection class changed (h2spec,
   Autobahn).
5. The sanitizer builds (`build_config_asan.rb`, `build_config_tsan.rb`)
   when the reactor, the pool or a buffer changed.
6. `tools/fuzz.sh` for one hour when a parser changed. The parsers
   are the head parser, the chunked decoder, the h2 frame parser, the
   websocket frame parser, the Accept parser, the date parser and the
   cookie parser. A finding becomes a test first, then a fix.
7. `bench/instructions.sh` against step 0.
8. Read the diff once more with rule 2 and rule 4. Does each
   declaration say what happens? Does anything hide?
9. When 3 to 8 moved something the wrong way, adjust and go to 2.
   When a full round changes nothing, the step is done.

The rounds are counted in the pull request text, with what each one
moved.

This container built the host config with `rake compile`. `rake test`
builds the debug config itself, and every test is the debug build's.
The conformance runs and the bench scripts need htgen, h2spec and
Autobahn, which this container does not have. Those run in CI or on
the author's machine.

### Step 0: the baseline

- Nothing in the tree changes. The thread change of Part 3.12 is not
  this plan's (decision 8). The baseline is taken on the tree as it
  is, at its own `--threads` default.
- Every script under `bench/` and every page under `docs/` is read,
  as CLAUDE.md asks, before the first measurement.
- `rake test` green on the base commit.
- `bench/instructions.sh` for the h1 floor, the h2 floor and one
  asset. The three counts go to `bench/results/` with the commit hash.
- The numbers of Part 2 go into the pull request text of every later
  step, measured again.

### Step 1: remove the dead, fix the tools

- Delete everything in Part 3.7.
- Delete the name form of `tools/rename-symbol.py`. The position form
  stays. `rename-batch.py` gets a check that its input is sorted
  bottom-up per file. It refuses otherwise.
- Name `mruby-c-ext-helpers` in `mrbgem.rake`. It is built through
  other gems already. Naming it says that this tree calls it.
- Fix the privacy levels of `webmachine-logd` to what the
  documentation says (Part 3.11), and add the bintest. The
  `server.cpp:622` warning moves to `full`. This is the one behaviour
  change in step 1, and it is a fix.
- Fix every declaration whose parameter name differs from its
  definition. The definition's name is copied into the declaration.
  This is a text change with no semantic risk. It removes about a
  third of Part 3.1.
- Check: build, suite, smoke. The counts of Part 2 are unchanged
  except for the dead lines.

### Step 2: the skeleton

- Write the headers of Part 4 as declarations only: namespaces by
  content, RFC section order inside, const arguments, return types.
  No bodies. No comments. Where an RFC clause used to be a comment, a
  one-line `static_assert` or a test name stands beside the
  declaration.
- Every name in the skeleton is checked against Part 1.1: a verb from
  the table, no made-up word, no metaphor.
- Each row of Part 3.9 becomes one declaration. Its arguments are the
  inputs the RFC names. Its state, where the RFC names one, is a value
  in and a value out. The row's right column goes into the pull
  request text beside the declaration, so that the review sees what
  the one method will collect.
- Nothing is called yet. The tree builds as before.
- This step is the review point. The user reads the headers and says
  what is missing and what is too much.

### Step 3: one decision loop

- `flow::walk` in `webmachine.hpp` becomes `next_decision`, the one
  pure step over the graph. `handle_request` becomes the one loop
  that drives it. The special cases of `run_engine` become the
  callbacks of the nodes they special-case. `flow::answer`,
  `walk_compiled`, `lands_on`, `reaches_a_node_that_reads_the_request`
  and `block_skips_are_the_graphs` go. `shortcut_for` becomes the
  table fill of decision 2.
- `next_decision(resource, request, state) -> Decision` is pure. The
  decision names the next callback to call or the status to answer.
  `handle_request` calls Ruby and calls `next_decision` again with the
  answer. No Ruby call happens inside `next_decision`.
- Check: `test/wm_flow.rb` (the flow oracle), the bintests, the
  instruction count. This step is the one most likely to move the
  count. It is measured alone for that reason.

### Step 4: one Request, one Response

- `ReqFacts`, `ReqValues` and `ReqView` become `http::Request`, with
  offsets into the head buffer. `Held`, `rebase`, `follow_copy` and
  `kReqValueSpans` go.
- `RunState` splits into `DecisionState`, `http::Response` and
  `SuspendedRequest`.
- The Ruby accessors keep their names, in this step and after
  (decision 1).
- `request_bind` and `response_bind` go. The Ruby `request` and
  `response` objects hold their request as a value. Each accessor
  reads `self`. `disp_override_` and `body_io_` go with them.
- Check: suite, smoke, count.

### Step 5: the pure functions under `http`, `cookies`, `problem_details`

- Each function of Part 4.1, 4.2 and 4.6 moves under its namespace,
  in RFC order, with const arguments and a return value. Its comments
  are deleted as it moves. Each fact goes to its destination of Part
  3.6 in the same commit.
- The second copies of Part 3.3 that these namespaces replace are
  deleted in the same step.
- The SWAR helpers are measured against `std::string_view::find_first_of`
  under rule 11. The count decides which one stays. What stays is one
  function with a test.
- Check: suite, smoke, count, and `grep -c '^\s*//'` on every moved
  file reads 0.

### Step 6: the connections

- `http1::Connection` from the h1 parts of `http1*.cpp`.
- `http2::Connection` from `http2.cpp` and `h2_wire.*`. `hpack` takes
  the encoder. Each piece is measured against ls-hpack under rule 11.
  ls-hpack is kept when the two are equal (decision 5).
- `websocket::Connection` and `websocket::permessage_deflate::Codec`
  from `http1_wire.cpp`, `websocket.cpp`, `wsconn.cpp` and the ws
  parts of `http2.cpp`.
- `sse::EventStream` from `sse.cpp` and the sse parts of both.
- The class `Http1` is gone at the end of this step.
- Check: suite, `tools/conformance.sh` (h2spec, Autobahn), smoke,
  count.

### Step 7: the reactor

- `Ring<App>` splits into the nine classes of Part 4.9. The App
  contact surface becomes one declared interface: the list of
  `App::*` calls `ring.hpp` makes today. There are about forty.
- The four scope guards become one. `Conn` in `ring.hpp` splits along
  the groups that are visible in it already.
- The file-scope state of `server.cpp`, `docroot.cpp`,
  `compute_task.cpp`, `resource.cpp` and `passwd.cpp` (Part 3.8)
  becomes one `Server` value built in `main` and one `Worker` value
  built per worker thread. Every function that read a global takes
  the value it needs as an argument.
- `boot` is one function. The acceptor and each answering thread call
  it. `answer_thread_boot` goes. The spin on `ring_fd` becomes the
  condition variable the pool uses already.
- Check: suite, `bintest/threads.rb`, `bintest/watcher.rb`,
  `bintest/zerocopy.rb`, smoke, count, and the sanitizer jobs.

### Step 8: the Resource and the Ruby surface

- The six parallel arrays and the sixteen `ValueCb` fields become the
  two `Callback` arrays. `cb_mask` is derived, not stored.
- Every webmachine-ruby name stays (decision 1). The duplicates are
  defined once each, in `mrblib/`, over the RFC accessors.
  `docs/reference/request-and-response.md` lists the gaps of the port.
- The three route tables become one `Router`.
- `request` is defined once.
- Check: suite, `bintest/resource.rb`, `bintest/application.rb`,
  `bintest/wmruby_app.rb`, smoke, count.

### Step 9: the last sweep

- Every remaining comment in the tree goes, the Rakefile and the build
  configs included. The Rakefile's regex over `reason()` and `kFaces`
  (used by `rake error_assets`) is replaced by a generated table. No
  Ruby reads C++ source text after that.
- A CI gate: `grep -rE '^\s*(//|/\*)' src test bintest tools mrblib`
  must print nothing. Over the Ruby files, the Rakefile and the build
  configs, `grep -rE '^\s*#' | grep -v '^#!'` must print nothing. The
  gate runs in the suite job.
- `clang-format --dry-run --Werror` over `src/`, `test/`, `tools/` and
  `bench/` joins the suite job as a gate, beside the comment gate.
  Every step from step 1 on formats the files it touched (rule 12).
  This last sweep changes nothing and only proves it.
- The 25 pages under `docs/` are read once more against the new
  names. `docs/explanation/reactor.md` and
  `docs/explanation/numbers-that-were-measured.md` are added. The
  `Held::Span` paragraph of CLAUDE.md is kept as history.
- Check: the whole of Part 2, measured again, in the pull request
  text.

## 7. What each step must not do

- No step changes what a client sees. The bintests are the contract.
  A step that needs a bintest changed names the RFC clause that says
  the old test was wrong.
- No step renames by text. A rename is clangd's position form,
  bottom-up, and the diff is read after.
- No step reformats a file it did not otherwise change. A file it did
  change is formatted whole, once, in the same commit.
- No step carries a session URL, a model name or a comment.
- No step states a number about speed that `bench/` did not produce.
