// The ZIP reader (#170), which is the one parser in this tree that
// eats a whole FILE FORMAT (#88).
//
// It is unfuzzed until now and it is the classic shape for it: a
// Central Directory of little-endian offsets and lengths, each one
// naming a place in the mapping to read next. Every zip CVE ever
// written lives in exactly that sentence. src/assets.cpp answers with
// named refusals - Zip64, encryption, a method that is neither 0 nor
// 8, a truncated directory - and this asks whether it answers them
// for EVERY malformed directory rather than the ones it was shown.
//
// The bytes are a file because Assets::open takes a path and mmaps
// it, which is the right shape for a table built once at setup - so
// the target writes the input out and hands over the name. One file
// per PROCESS (the pid is in it), because -fork runs thirty of these
// at once and they must not share a scratch file.
//
// After a directory that parsed, the REQUEST half runs too: find() is
// a byte compare against the table's names, and verdict() turns
// Range/If-Match/If-None-Match into a status. Both take strings the
// same input chose.
//
//   tools/fuzz.sh   (every target; this one is 'assets')
#include "../../src/assets.cpp"  // NOLINT: instrumented, not linked

#include <sys/uio.h>
#include <unistd.h>

#include <ctime>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// The tree namespaces its halves; this target speaks all three.
using namespace webmachine;  // NOLINT: a test binary, one translation unit

namespace {

const char* scratch_path() {
  static std::string p = [] {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "/tmp/wm-assets-fuzz-%d.zip", static_cast<int>(::getpid()));
    return std::string(buf);
  }();
  return p.c_str();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // 22 bytes is the shortest possible End of Central Directory record,
  // and Assets::open refuses anything below it by fstat alone.
  if (size < 22 || size > (1u << 20)) return 0;

  const char* path = scratch_path();
  std::FILE* f = std::fopen(path, "wbe");
  if (f == nullptr) return 0;
  const bool wrote = std::fwrite(data, 1, size, f) == size;
  std::fclose(f);
  if (!wrote) return 0;

  Assets a;
  char err[256];
  if (!a.open(path, err, sizeof(err))) return 0;

  // A directory that parsed. Now the REQUEST half.
  //
  // find() is a byte compare against the table's own names, so a
  // mutated archive is only looked up successfully when its name
  // survived - which is why the fixed probes are here next to the
  // input-derived ones. Without them the whole response-building half
  // of this tier is unreachable, and it was: a stall report on this
  // very target named answer_206_head (94 edges), answer_416_head
  // (31), answer_head (19), wire_iov, copy_wire and verdict as never
  // entered. answer_206_head builds a Content-Range out of numbers a
  // Range header chose - that is the last place in this tree that
  // should go untested.
  // WITH the leading slash and sometimes with a query: find() takes
  // the REQUEST-TARGET in origin-form and strips both itself, so a
  // caller that pre-strips them (as this target did at first, and got
  // a null for every lookup) tests nothing.
  static const char* const kNames[] = {"/index.html", "/index.html?v=1", "/app.css",
                                       "/app.js", "/index.htm", "/"};
  const size_t half = size / 2;
  const char* probe = reinterpret_cast<const char*>(data);

  const auto exercise = [&](AssetEntry* e) {
    if (e == nullptr) return;
    flow::ReqFacts facts;
    http::ReqValues vals;
    // The header values this tier reads, all pointing into the
    // fuzzer's own bytes.
    vals.range = probe;
    vals.range_len = half;
    vals.if_range = probe + half;
    vals.if_range_len = size - half;
    vals.if_match = probe;
    vals.if_match_len = half;
    vals.if_none_match = probe + half;
    vals.if_none_match_len = size - half;
    vals.accept_encoding = probe;
    vals.accept_encoding_len = half;
    facts.has_if_match = true;
    facts.has_if_none_match = true;
    facts.has_accept_encoding = true;

    // 5.6.7's date, which every head below patches in at a fixed
    // offset - a real one, so the patch writes what it expects to.
    char date[http::kDateLen];
    const time_t sec = 1416441000;
    struct tm tm {};
    gmtime_r(&sec, &tm);
    http::date_core(date, tm);

    std::string sink;
    for (const flow::Method m : {flow::Method::kGet, flow::Method::kHead,
                                 flow::Method::kPost, flow::Method::kOther}) {
      const uint16_t status = a.verdict(*e, m, facts, vals);
      sink.clear();
      a.answer_head(*e, status, Assets::kKeep, date, sec, sink);
    }

    // 9110 14.1.2 into 14.4: the window a Range chose, turned into a
    // Content-Range and a send length. The window always comes from
    // parse_range, so it is one this tier would really build -
    // fabricating first/last here would test arithmetic nobody runs.
    //
    // FOUR range values, and the last three are the point. The raw
    // input is a zip, so it never begins with "bytes=" - and even
    // prefixed with the unit it fails at the first byte, because what
    // follows has to be DIGITS. parse_range answered kNone every
    // time, which left answer_206_head (94 edges), answer_416_head,
    // wire_iov and copy_wire unentered, exactly as a stall report on
    // this target said.
    //
    // So the three forms 14.1.2 defines are SPELLED here and the
    // numbers in them come from the input. The grammar is not the
    // thing under test - a Range that does not match it is refused in
    // six lines and that path is covered by the raw value below. What
    // is under test is what the tier BUILDS from numbers a stranger
    // chose: a Content-Range, a send length, an iovec. Fixing the
    // shape and fuzzing the numbers is the same trick the dictionary
    // plays for every other target.
    const size_t complete = Assets::wire_len(*e);
    const auto num = [&](size_t at) -> unsigned long long {
      // Spread across magnitudes, so a window lands inside, exactly
      // on, and far past the representation.
      const unsigned shift = (data[at % size] & 0x1f);
      return (static_cast<unsigned long long>(data[(at + 1) % size]) + 1ULL) << (shift & 31);
    };
    char closed[64], openended[64], suffix[64];
    std::snprintf(closed, sizeof(closed), "bytes=%llu-%llu", num(0), num(2));
    std::snprintf(openended, sizeof(openended), "bytes=%llu-", num(4));
    std::snprintf(suffix, sizeof(suffix), "bytes=-%llu", num(6));
    const char* rv[4] = {vals.range, closed, openended, suffix};
    const size_t rn[4] = {vals.range_len, std::strlen(closed), std::strlen(openended),
                          std::strlen(suffix)};
    for (int k = 0; k < 4; k++) {
      size_t first = 0, last = 0;
      switch (http::parse_range(rv[k], rn[k], complete, &first, &last)) {
        case http::RangeParse::kOne: {
          sink.clear();
          a.answer_206_head(*e, Assets::kPlain, first, last, date, sink);
          sink.clear();
          Assets::copy_wire(*e, first, last - first + 1, sink);
          struct iovec iov[4];
          Assets::wire_iov(*e, first, last - first + 1, iov);
          break;
        }
        case http::RangeParse::kUnsat:
          sink.clear();
          a.answer_416_head(*e, Assets::kClose, date, sink);
          break;
        case http::RangeParse::kNone:
          break;
      }
    }
  };

  for (const char* nm : kNames) exercise(a.find(nm, std::strlen(nm)));
  for (const size_t len : {size_t{0}, size_t{1}, half, size}) exercise(a.find(probe, len));
  return 0;
}
