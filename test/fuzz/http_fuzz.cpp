// The 9110 VALUE parsers, driven directly (#88).
//
// Why this target exists at all: these functions are reached in
// production, but they are NOT reached by test/fuzz/feed_fuzz.cpp.
// That target builds a konst Resource and no asset table, so
// `bound_` is false and `assets_` is null - and every one of the
// parsers below sits behind one of those two. Range and If-Range are
// read only by the asset tier; the ETag comparisons only when a
// resource or an asset carries a tag; gzip_acceptable only on the
// dynamic-body path. Fuzzing feed() for eight hours would never
// execute a line of them.
//
// They are also exactly the shape that rewards fuzzing: a header
// value a stranger wrote, turned into NUMBERS and OFFSETS - a range
// window measured against a length, a decimal parsed with overflow
// builtins, a list walked by index. No allocation, no IO, no state
// between calls, so a finding here is a finding about arithmetic and
// nothing else.
//
//   tools/fuzz.sh   (every target; this one is 'http')
#include "../../src/webmachine.hpp"  // NOLINT: http:: folded in here (741d09a); header-only, instrumented here

#include <cstdint>
#include <string>

// The tree namespaces both halves; this target speaks only these two.
using namespace webmachine;      // NOLINT: a test binary, one translation unit

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 3) return 0;
  // Byte 0 splits the input into a NAME half and a VALUE half, so one
  // corpus entry drives both the dispatch and the parsers, and the
  // fuzzer can move the boundary. Byte 1 is the representation length
  // a range is measured against - including ZERO, which is a real
  // asset (an empty file is a legal zip entry) and the edge every
  // range arithmetic has to survive.
  const size_t split = static_cast<size_t>(data[0]) % (size - 2);
  const size_t complete = static_cast<size_t>(data[1]) * 4096u;
  const char* p = reinterpret_cast<const char*>(data) + 2;
  const size_t n = size - 2;
  const char* name = p;
  const size_t nlen = split;
  const char* value = p + split;
  const size_t vlen = n - split;

  // The one dispatch every header goes through, with the 9112 wire
  // names arriving at the functor exactly as http1.cpp's do.
  flow::ReqFacts facts;
  http::ReqValues vals;
  facts.method = http::parse_method(name, nlen);
  size_t wire_seen = 0;
  http::header_switch(name, nlen, value, vlen, facts, vals,
                      [&](const char*, size_t, const char*, size_t vl) { wire_seen += vl; });

  // RFC 9112 6.2: 1*DIGIT with overflow builtins.
  size_t cl = 0;
  http::parse_content_length(value, vlen, &cl);

  // RFC 9110 14.1.2: the window, against a length the value did not
  // choose. first/last are only meaningful on kOne, and reading them
  // otherwise is what a caller must not do - so this reads them the
  // way the asset tier does.
  size_t first = 0, last = 0;
  if (http::parse_range(value, vlen, complete, &first, &last) == http::RangeParse::kOne) {
    // kOne implies complete >= 1 (complete == 0 answers kUnsat), so the
    // window must lie inside the representation. It is asserted rather
    // than assumed because the asset tier turns it straight into a
    // Content-Range and a send length - a window past the end is an
    // information leak, and ASan cannot see arithmetic.
    if (first > last || last >= complete) __builtin_trap();
  }

  // 13.1.1/13.1.2 and 14.2: the list walks, compared against a tag
  // the input also chose - so the tag is sometimes a prefix of a
  // member, sometimes longer than the whole list, sometimes empty.
  http::etag_list_match(value, vlen, name, nlen, false);
  http::etag_list_match(value, vlen, name, nlen, true);
  http::if_range_matches(value, vlen, name, nlen);
  http::star_value(value, vlen);

  // 12.5.3: q-values and the * fallback.
  http::gzip_acceptable(value, vlen);

  // 5.6.7 and 6.2's spelling half, which take numbers rather than
  // bytes but share the buffers everything above writes into.
  char cl_buf[40];
  http::spell_content_length(cl_buf, cl);
  return 0;
}
