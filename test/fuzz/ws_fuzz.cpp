// ALL of src/websocket.hpp (#88/#175): a frame off a buffer the peer
// wrote and unmasked in place, the close payload read back out, the
// handshake key hashed, and the two builders. No connection, no
// mruby, no message assembly - the header is protocol truth and
// nothing else, so this target is the same shape as the header.
//
// The builders and accept_key were added after a 30-worker run made
// the gap visible: the target covered 62 of the module's 137 blocks
// and stopped growing after ten seconds, because parse() and
// read_close() were the only two functions it ever called. The rest
// was compiled in and unreachable - which no number of worker-hours
// fixes, and which a coverage number reads as "saturated" rather than
// "half the file is not being tested".
//
// accept_key is the one that matters: RFC 6455 4.2.2 has this
// endpoint SHA-1 and base64 sixty bytes a stranger chose, BEFORE
// anything has authenticated anything. It is a fixed-size buffer fed
// a caller-controlled length, which is the oldest bug shape there
// is.
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
      // RFC 6455 5.2 in the order the reader demands it: header_need says
      // how many octets the next decision wants, and only once they have
      // all arrived may read_head touch them - it reads unconditionally.
      const unsigned char* h = reinterpret_cast<const unsigned char*>(buf.data()) + off;
      const size_t left = buf.size() - off;
      if (left < 2) break;
      const uint8_t have = left > 14 ? 14 : static_cast<uint8_t>(left);
      const uint8_t need = webmachine::ws::header_need(h, have);
      if (need > left) break;
      const webmachine::ws::Head hd = webmachine::ws::read_head(h, pass != 0);
      if (hd.err != webmachine::ws::Head::Err::kNone) break;
      if (hd.payload_length > (1u << 20)) break;
      if (need + hd.payload_length > left) break;

      // The unmask is the other half a stranger's bytes reach, and it
      // writes - so it gets its own buffer of exactly the promised size.
      std::vector<char> plain(static_cast<size_t>(hd.payload_length) + 1);
      webmachine::ws::unmask_copy(plain.data(), buf.data() + off + need,
                                  static_cast<size_t>(hd.payload_length),
                                  h + hd.masking_key_at, 0);
      if (hd.opcode == webmachine::ws::kClose) {
        uint16_t cc = 0;
        const char* reason = nullptr;
        size_t rlen = 0;
        webmachine::ws::read_close(plain.data(), static_cast<size_t>(hd.payload_length), cc,
                                   &reason, &rlen);
      }
      const size_t consumed = need + static_cast<size_t>(hd.payload_length);
      if (consumed == 0) break;
      off += consumed;
      if (off >= buf.size()) break;
    }
  }

  // RFC 6455 4.2.2's handshake half. The key is whatever arrived -
  // the 24-character check is the thing under test, not a
  // precondition, so this hands it every length the corpus has.
  char accept[28];
  webmachine::ws::accept_key(reinterpret_cast<const char*>(data), size, accept);
  if (size >= 24) {
    webmachine::ws::accept_key(reinterpret_cast<const char*>(data), 24, accept);
  }

  // 5.2 and 7.1.6, the writing direction: lengths and a reason the
  // input chose, into the fixed buffers the header promises are
  // enough. build_close_payload truncates at 123 bytes and that
  // truncation is the whole point of driving it with long input.
  char head[10];
  const uint8_t op = data[0] & 0x0f;
  const size_t plen = static_cast<size_t>(data[size - 1]) << ((data[0] >> 4) & 0x1f);
  webmachine::ws::build_header(op, (data[0] & 0x80) != 0, (data[0] & 0x40) != 0, plen, head);
  char close_payload[125];
  webmachine::ws::build_close_payload(
      static_cast<uint16_t>((data[0] << 8) | data[size - 1]),
      reinterpret_cast<const char*>(data), size, close_payload);
  return 0;
}
