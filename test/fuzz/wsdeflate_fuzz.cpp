// permessage-deflate's negotiation and its codec (#88/#175 round two).
//
// The negotiation is a HEADER PARSER fed by whoever opened the socket -
// RFC 7692 4.2's extension list, with quoted strings, duplicate
// parameters and values that are not numbers - and this tree writes
// its own. That is the profile every framer here has: attacker bytes
// in, a small state machine, no allocation the peer chose the size of.
//
// The codec half is fuzzed through what it actually does on the wire:
// whatever the negotiation just settled on is used to inflate the REST
// of the input, with the message cap the connection would apply. zlib
// itself is not the target (it is fuzzed where it lives); the loop
// around it is - the sink that must stop at max_message, the tail that
// 7.2.2 puts back, the reset a stream that ended demands.
//
//   tools/fuzz.sh wsdeflate
#include "../../src/wsdeflate.hpp"  // NOLINT: instrumented, not linked

#include <cstdint>
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
  return 0;
}
