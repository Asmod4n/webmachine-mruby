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

#include <unistd.h>

#include <cstdint>
#include <cstdio>
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
  if (a.open(path, err, sizeof(err))) {
    // A directory that parsed. Now the request side, with names the
    // same input chose - so a lookup is sometimes a hit, usually a
    // miss, and occasionally a prefix of a real entry.
    const size_t half = size / 2;
    const char* probe = reinterpret_cast<const char*>(data);
    for (const size_t len : {size_t{0}, size_t{1}, half, size}) {
      AssetEntry* e = a.find(probe, len);
      if (e == nullptr) continue;
      flow::ReqFacts facts;
      http::ReqValues vals;
      // The three header values the asset tier reads, all pointing
      // into the fuzzer's own bytes.
      vals.range = probe;
      vals.range_len = half;
      vals.if_range = probe + half;
      vals.if_range_len = size - half;
      vals.if_match = probe;
      vals.if_match_len = half;
      vals.if_none_match = probe + half;
      vals.if_none_match_len = size - half;
      facts.has_if_match = true;
      facts.has_if_none_match = true;
      for (const flow::Method m : {flow::Method::kGet, flow::Method::kHead,
                                   flow::Method::kPost, flow::Method::kOther}) {
        a.verdict(*e, m, facts, vals);
      }
      size_t first = 0, last = 0;
      http::parse_range(vals.range, vals.range_len, Assets::wire_len(*e), &first,
                        &last);
    }
  }
  return 0;
}
