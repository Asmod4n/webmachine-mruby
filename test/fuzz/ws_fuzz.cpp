// The websocket framing alone (#88/#175): one frame off a buffer the
// peer wrote, unmasked in place. No connection, no mruby, no message
// assembly - src/websocket.hpp is protocol truth and nothing else, so
// this target is the same shape as the header.
//
//   tools/fuzz.sh ws
#include "../../src/websocket.cpp"  // NOLINT: instrumented, not linked

#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;
  // Both halves of the RSV1 question on the same bytes (#175 round
  // two): with permessage-deflate negotiated the bit is legal on a
  // first data frame, without it nothing may carry it - and a frame
  // the one accepts and the other refuses is exactly where the two
  // readers could drift apart.
  for (int pass = 0; pass < 2; pass++) {
    // The buffer is COPIED because the parser unmasks in place - which
    // is also what the real caller hands it: this process's own pool.
    // Once PER PASS, because the first pass rewrote it.
    std::vector<char> buf(reinterpret_cast<const char*>(data),
                          reinterpret_cast<const char*>(data) + size);
    size_t off = 0;
    for (;;) {
      webmachine::ws::Frame f;
      uint16_t code = 0;
      const webmachine::ws::Parse r = webmachine::ws::parse(
          buf.data() + off, buf.size() - off, 1u << 20, pass != 0, f, code);
      if (r != webmachine::ws::Parse::kOk) break;
      if (f.opcode == webmachine::ws::kClose) {
        uint16_t cc = 0;
        const char* reason = nullptr;
        size_t rlen = 0;
        webmachine::ws::read_close(f.payload, f.len, cc, &reason, &rlen);
      }
      if (f.consumed == 0) break;
      off += f.consumed;
      if (off >= buf.size()) break;
    }
  }
  return 0;
}
