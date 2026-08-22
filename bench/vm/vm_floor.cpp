// The copy floor (Gebot 10): the naive shape - copy the request INTO
// the VM as a fresh String, call a Ruby handler, copy the response OUT.
// Whatever cleverness later touches the VM boundary must beat these
// numbers measurably, or the naive shape stays. GC pauses triggered by
// the per-call garbage are part of the number on purpose: they are the
// real cost of this shape.
#include <benchmark/benchmark.h>
#include <mruby.h>
#include <mruby/class.h>
#include <mruby/dump.h>   // mrb_load_irep_file: bytecode, never source (#100)
#include <mruby/string.h>

#include <cstdio>
#include <cstring>

#include "../../src/flow_walk.hpp"
#include "../../src/resource.hpp"

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

// Tier 0 next to tier 1: the full decision graph for a konst resource,
// walked without the VM. Its distance to BM_copy_floor_* is the price
// difference between a konst answer and a budgeted VM entry.
void BM_flow_tier0_get(benchmark::State& state) {
  const webmachine::flow::KonstAnswers k =
      webmachine::flow::default_konst(webmachine::flow::Method::kGet);
  webmachine::flow::ReqFacts req;  // the wrk shape: plain GET, no conditionals
  for (auto _ : state) {
    benchmark::DoNotOptimize(req);
    uint16_t status = webmachine::flow::walk(req, k);
    benchmark::DoNotOptimize(status);
  }
}
BENCHMARK(BM_flow_tier0_get)->Unit(benchmark::kNanosecond);

// The conditional-request path: If-None-Match: * short-circuits to 304.
void BM_flow_tier0_304(benchmark::State& state) {
  const webmachine::flow::KonstAnswers k =
      webmachine::flow::default_konst(webmachine::flow::Method::kGet);
  webmachine::flow::ReqFacts req;
  req.has_if_none_match = true;
  req.inm_star = true;
  for (auto _ : state) {
    benchmark::DoNotOptimize(req);
    uint16_t status = webmachine::flow::walk(req, k);
    benchmark::DoNotOptimize(status);
  }
}
BENCHMARK(BM_flow_tier0_304)->Unit(benchmark::kNanosecond);

// The same walks with the konst vector folded at compile time: the
// graph reduced to a chain of request-fact tests. Interpreted vs
// compiled is a Gebot-10 A/B - the loser goes.
void BM_flow_tier0_get_compiled(benchmark::State& state) {
  constexpr auto kK = webmachine::flow::default_konst(webmachine::flow::Method::kGet);
  webmachine::flow::ReqFacts req;
  for (auto _ : state) {
    benchmark::DoNotOptimize(req);
    uint16_t status = webmachine::flow::walk_compiled<kK>(req);
    benchmark::DoNotOptimize(status);
  }
}
BENCHMARK(BM_flow_tier0_get_compiled)->Unit(benchmark::kNanosecond);

void BM_flow_tier0_304_compiled(benchmark::State& state) {
  constexpr auto kK = webmachine::flow::default_konst(webmachine::flow::Method::kGet);
  webmachine::flow::ReqFacts req;
  req.has_if_none_match = true;
  req.inm_star = true;
  for (auto _ : state) {
    benchmark::DoNotOptimize(req);
    uint16_t status = webmachine::flow::walk_compiled<kK>(req);
    benchmark::DoNotOptimize(status);
  }
}
BENCHMARK(BM_flow_tier0_304_compiled)->Unit(benchmark::kNanosecond);

// The runtime tier on real bound resources: the whole run inside one
// VM frame (naked yields under the wrapper's TRY). One and four
// callbacks. A per-node-entry variant was 26ns faster at one callback
// (forgecore 230 vs 256ns) and died anyway: it cannot host
// cross-callback arena lifetimes without ivars - the frame IS the
// memory model.
webmachine::Resource g_res1;
webmachine::Resource g_res4;

// Bytecode, never source (#100): the binary this measures carries no
// compiler, so this one does not either - bench/vm.sh runs mrbc over
// bench/vm/*.rb first and hands the .mrb paths in.
bool load_irep(mrb_state* m, const char* path) {
  FILE* f = std::fopen(path, "rb");
  if (f == nullptr) {
    std::fprintf(stderr, "bench: cannot open %s (run bench/vm.sh, not the binary)\n", path);
    return false;
  }
  mrb_load_irep_file(m, f);
  std::fclose(f);
  return m->exc == nullptr;
}

bool bind_bench_resource(const char* cls, const char* mrb_path, webmachine::Resource& out) {
  char err[256];
  // Its own VM: the two bench resources must not see each other's
  // classes. The fold is what route.add does (#116) - the same call,
  // without a listener in front of it.
  mrb_state* own = mrb_open();
  if (own == nullptr) return false;
  if (!load_irep(own, mrb_path)) {
    std::fprintf(stderr, "bench bind: %s raised while loading\n", cls);
    return false;
  }
  if (!webmachine::resource_fold(own, mrb_obj_value(mrb_class_get(own, cls)), out, err,
                                 sizeof(err))) {
    std::fprintf(stderr, "bench bind: %s\n", err);
    return false;
  }
  return true;
}

void BM_runtime_1cb(benchmark::State& state) {
  webmachine::flow::ReqFacts facts;
  std::string body;
  bool have = false;
  for (auto _ : state) {
    // No request view (#116 slice 4): these two measure the VM entry
    // and the callbacks, and a callback that asked `request` anything
    // would be measuring the accessor instead.
    uint16_t st = webmachine::resource_run(g_res1, facts, nullptr, &body, &have);
    benchmark::DoNotOptimize(st);
    benchmark::DoNotOptimize(body);
  }
}
BENCHMARK(BM_runtime_1cb)->Unit(benchmark::kMicrosecond);

void BM_runtime_4cb(benchmark::State& state) {
  webmachine::flow::ReqFacts facts;
  std::string body;
  bool have = false;
  for (auto _ : state) {
    uint16_t st = webmachine::resource_run(g_res4, facts, nullptr, &body, &have);
    benchmark::DoNotOptimize(st);
    benchmark::DoNotOptimize(body);
  }
}
BENCHMARK(BM_runtime_4cb)->Unit(benchmark::kMicrosecond);

}  // namespace

int main(int argc, char** argv) {
  mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "mrb_open failed\n");
    return 1;
  }
  if (!load_irep(mrb, "bench/vm/handlers.mrb")) {
    std::fprintf(stderr, "handler setup raised\n");
    return 1;
  }
  if (!bind_bench_resource("BenchCounter", "bench/vm/bench_counter.mrb", g_res1) ||
      !bind_bench_resource("BenchMulti", "bench/vm/bench_multi.mrb", g_res4)) {
    std::fprintf(stderr, "bench resource setup failed\n");
    return 1;
  }
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  mrb_close(mrb);
  return 0;
}
