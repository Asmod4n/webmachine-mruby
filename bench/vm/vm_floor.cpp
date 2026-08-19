// The copy floor (Gebot 10): the naive shape - copy the request INTO
// the VM as a fresh String, call a Ruby handler, copy the response OUT.
// Whatever cleverness later touches the VM boundary must beat these
// numbers measurably, or the naive shape stays. GC pauses triggered by
// the per-call garbage are part of the number on purpose: they are the
// real cost of this shape.
#include <benchmark/benchmark.h>
#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/string.h>

#include <cstdio>
#include <cstring>

namespace {

mrb_state* mrb = nullptr;

constexpr char kSmall[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
// A browser-shaped head: what real traffic copies in, not the minimum.
constexpr char kBrowser[] =
    "GET /index.html HTTP/1.1\r\n"
    "Host: example.org\r\n"
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8\r\n"
    "Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n"
    "Accept-Encoding: gzip, deflate, br, zstd\r\n"
    "Connection: keep-alive\r\n"
    "Cookie: sid=5b0aa4a2f4c8f10a9d43e0a4c8b5f0aa4a2f4c8f1; theme=dark; consent=1\r\n"
    "Upgrade-Insecure-Requests: 1\r\n"
    "Sec-Fetch-Dest: document\r\n"
    "Sec-Fetch-Mode: navigate\r\n"
    "Sec-Fetch-Site: none\r\n"
    "\r\n";

// One VM entry, nothing copied: the entry cost itself.
void BM_vm_entry(benchmark::State& state) {
  for (auto _ : state) {
    const int ai = mrb_gc_arena_save(mrb);
    mrb_value r = mrb_funcall(mrb, mrb_top_self(mrb), "wm_noop", 0);
    benchmark::DoNotOptimize(r);
    if (mrb->exc != nullptr) {
      mrb->exc = nullptr;
      state.SkipWithError("ruby raised");
      break;
    }
    mrb_gc_arena_restore(mrb, ai);
  }
}
BENCHMARK(BM_vm_entry)->Unit(benchmark::kMicrosecond);

void copy_floor(benchmark::State& state, const char* req, size_t reqlen) {
  char out[256];
  for (auto _ : state) {
    const int ai = mrb_gc_arena_save(mrb);
    mrb_value rreq = mrb_str_new(mrb, req, reqlen);  // copy in
    mrb_value resp = mrb_funcall(mrb, mrb_top_self(mrb), "wm_handle", 1, rreq);
    if (mrb->exc != nullptr || !mrb_string_p(resp)) {
      mrb->exc = nullptr;
      state.SkipWithError("handler failed");
      break;
    }
    const size_t n = RSTRING_LEN(resp) < static_cast<mrb_int>(sizeof(out))
                         ? static_cast<size_t>(RSTRING_LEN(resp))
                         : sizeof(out);
    std::memcpy(out, RSTRING_PTR(resp), n);  // copy out
    benchmark::DoNotOptimize(out);
    mrb_gc_arena_restore(mrb, ai);
  }
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                          static_cast<int64_t>(reqlen));
}

void BM_copy_floor_small(benchmark::State& state) { copy_floor(state, kSmall, sizeof(kSmall) - 1); }
BENCHMARK(BM_copy_floor_small)->Unit(benchmark::kMicrosecond);

void BM_copy_floor_browser(benchmark::State& state) {
  copy_floor(state, kBrowser, sizeof(kBrowser) - 1);
}
BENCHMARK(BM_copy_floor_browser)->Unit(benchmark::kMicrosecond);

// Same copy floor, but the symbol is interned once and the call goes
// through funcall_argv: the delta to BM_copy_floor_small is what name
// lookup costs per entry.
void BM_copy_floor_cached_sym(benchmark::State& state) {
  char out[256];
  const mrb_sym sym = mrb_intern_lit(mrb, "wm_handle");
  for (auto _ : state) {
    const int ai = mrb_gc_arena_save(mrb);
    mrb_value rreq = mrb_str_new(mrb, kSmall, sizeof(kSmall) - 1);
    mrb_value resp = mrb_funcall_argv(mrb, mrb_top_self(mrb), sym, 1, &rreq);
    if (mrb->exc != nullptr || !mrb_string_p(resp)) {
      mrb->exc = nullptr;
      state.SkipWithError("handler failed");
      break;
    }
    const size_t n = RSTRING_LEN(resp) < static_cast<mrb_int>(sizeof(out))
                         ? static_cast<size_t>(RSTRING_LEN(resp))
                         : sizeof(out);
    std::memcpy(out, RSTRING_PTR(resp), n);
    benchmark::DoNotOptimize(out);
    mrb_gc_arena_restore(mrb, ai);
  }
}
BENCHMARK(BM_copy_floor_cached_sym)->Unit(benchmark::kMicrosecond);

}  // namespace

int main(int argc, char** argv) {
  mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "mrb_open failed\n");
    return 1;
  }
  mrb_load_string(mrb,
                  "def wm_noop; end\n"
                  "def wm_handle(req)\n"
                  "  \"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK\"\n"
                  "end\n");
  if (mrb->exc != nullptr) {
    std::fprintf(stderr, "handler setup raised\n");
    return 1;
  }
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  mrb_close(mrb);
  return 0;
}
