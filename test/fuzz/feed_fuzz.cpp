// The framers, fed by libFuzzer (#88). What gets instrumented is
// exactly what touches bytes a stranger chose: the h1 head path, the
// h2 frame and HPACK path, and - through its own target next door -
// the websocket framing. Everything else (mruby, ls-hpack, phr) comes
// from libmruby.a uninstrumented, which is why those .cpp files are
// INCLUDED here rather than linked: the archive member is then never
// pulled, and the code under test is the code ASan watches.
//
// No mruby state is needed and none is built: the route's Resource is
// default-constructed, so it is konst - `bound` is false and the VM is
// never entered. This target is about the FRAMER, and a framer that
// crashes does so before any callback would run.
//
//   tools/fuzz.sh feed
#include "../../src/http1.cpp"    // NOLINT: see above
#include "../../src/http2.cpp"    // NOLINT
#include "../../src/websocket.cpp"  // NOLINT

#include <cstdint>
#include <string>
#include <vector>

namespace {

// RFC 9113 3.4's client preface, so the fuzzer does not have to
// discover 24 fixed bytes before it can reach the h2 code at all.
constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

webmachine::Http1& app() {
  static webmachine::RouteTable* table = [] {
    auto* t = new webmachine::RouteTable();
    t->open();
    t->splat();
    t->commit();
    return t;
  }();
  static webmachine::Resource* res = new webmachine::Resource();
  static const webmachine::Resource* list[1] = {res};
  static webmachine::Http1* a = new webmachine::Http1(*table, list, 1);
  return *a;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  // Byte 0 picks the protocol (the h2 preface is prepended rather than
  // discovered); byte 1 is the chunk width, so the SPLIT paths - the
  // carry, a header cut in half, a frame cut in half - are reachable
  // instead of only whole-buffer inputs.
  const uint8_t mode = data[0] & 1;
  size_t chunk = static_cast<size_t>(data[1]) + 1;
  data += 2;
  size += -2;

  webmachine::Http1::Conn conn;
  conn.reset(0, true);
  std::string sink;

  std::string wire;
  if (mode == 1) wire.assign(kPreface, sizeof(kPreface) - 1);
  wire.append(reinterpret_cast<const char*>(data), size);

  for (size_t off = 0; off < wire.size();) {
    const size_t n = wire.size() - off < chunk ? wire.size() - off : chunk;
    // The Ring hands over the pool buffer, which this process owns and
    // the websocket reader unmasks in place - so the copy is what the
    // real caller does, not a convenience.
    std::vector<char> buf(wire.begin() + static_cast<long>(off),
                          wire.begin() + static_cast<long>(off + n));
    if (!app().feed(conn, buf.data(), buf.size(), sink)) break;
    sink.clear();
    off += n;
  }
  return 0;
}
