// permessage-deflate's negotiation and its codec (#88/#175 round two).
//
// The negotiation is a HEADER PARSER fed by whoever opened the socket -
// RFC 7692 4.2's extension list, with quoted strings, duplicate
// parameters and values that are not numbers - and this tree writes
// its own. That is the profile every framer here has: attacker bytes
// in, a small state machine, no allocation the peer chose the size of.
//
// AND A ROUND TRIP, which is the only part of this file that checks a
// PROPERTY rather than just reaching code. Until it was added, this
// tree's COMPRESSOR was never fuzzed at all - the target inflated
// attacker bytes and Codec::compress never ran, even though its
// output is what a browser has to decode. inflate(compress(x)) == x
// is a fact no sanitizer can see: a window desync, a mishandled
// sync-flush tail or an asymmetric reset between the two directions
// all produce well-formed memory and wrong bytes.
//
// The receiving codec is configured as the PEER of the sending one -
// its client window is the sender's server window, its client
// context-takeover the sender's server one - because that is the
// pairing RFC 7692 negotiates, and a round trip that configured both
// sides the same would not test the negotiation at all.
//
// Several messages through ONE pair, in order, so context takeover is
// under test: the second message's stream references the first's
// window, and only a receiver that kept the same history decodes it.
//
// The codec half is fuzzed through what it actually does on the wire:
// whatever the negotiation just settled on is used to inflate the REST
// of the input, with the message cap the connection would apply. zlib
// itself is not the target (it is fuzzed where it lives); the loop
// around it is - the sink that must stop at max_message, the tail that
// 7.2.2 puts back, the reset a stream that ended demands.
//
//   tools/fuzz.sh wsdeflate
#include "../../src/webmachine.hpp"  // NOLINT: wsdeflate folded in here (741d09a); header-only, so including it instruments it

#include <cstdint>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;
  // One byte says where the header value ends and the compressed
  // payload begins, so a single corpus entry exercises both halves and
  // the fuzzer can move the boundary.
  const size_t split = static_cast<size_t>(data[0]) % size;
  const char* p = reinterpret_cast<const char*>(data) + 1;
  const size_t n = size - 1;

  webmachine::wsdeflate::Params params;
  std::string answer;
  const bool on = webmachine::wsdeflate::negotiate(p, split < n ? split : n, params, answer);
  if (!on) return 0;

  webmachine::wsdeflate::Codec codec;
  codec.configure(params);
  size_t total = 0;
  const size_t kMax = 1u << 20;  // the same shape kMaxWsMessageDefault has
  auto sink = [&](const char*, size_t got) {
    total += got;
    return total <= kMax;
  };
  const size_t at = split < n ? split : n;
  if (codec.inflate_some(p + at, n - at, sink) != 0) return 0;
  codec.inflate_finish(sink);

  // ---- the round trip
  webmachine::wsdeflate::Codec tx;
  tx.configure(params);
  webmachine::wsdeflate::Params peer = params;
  peer.client_max_window_bits = params.server_max_window_bits;
  peer.client_no_context_takeover = params.server_no_context_takeover;
  webmachine::wsdeflate::Codec rx;
  rx.configure(peer);

  const size_t body_len = n - at;
  const char* body = p + at;
  for (int msg = 0; msg < 3; msg++) {
    // Three messages out of one payload, so the second and third ride
    // a window the first filled.
    const size_t lo = body_len * static_cast<size_t>(msg) / 3;
    const size_t hi = body_len * static_cast<size_t>(msg + 1) / 3;
    const char* m = body + lo;
    const size_t mn = hi - lo;

    std::string wire;
    if (!tx.compress(m, mn, wire)) break;  // zlib refused: identity is the answer

    std::string back;
    auto keep = [&](const char* q, size_t qn) {
      back.append(q, qn);
      return back.size() <= kMax;
    };
    // Anything but 0 here is this tree failing to read its own
    // compressor, which is a bug however it happened.
    if (rx.inflate_some(wire.data(), wire.size(), keep) != 0) __builtin_trap();
    if (rx.inflate_finish(keep) != 0) __builtin_trap();
    if (back.size() != mn || (mn != 0 && std::memcmp(back.data(), m, mn) != 0)) {
      __builtin_trap();
    }
  }
  return 0;
}
