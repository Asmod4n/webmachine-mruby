# WebSocket round one (#175): the handshake key and the framing,
# driven from outside the product through WsVectors (test/ws_vectors.cpp).
# Every case here is RFC 6455's own text - this is the layer Autobahn
# will later hammer over a socket, proven first where a failure names
# its own line.

# Array#pack is not in the unit VM's gem set; the two big-endian
# spellings this file needs are three lines.
def ws_be16(n)
  (((n >> 8) & 0xff).chr + (n & 0xff).chr).b
end

def ws_be64(n)
  out = ''.b
  7.downto(0) { |i| out << ((n >> (i * 8)) & 0xff).chr }
  out
end

def ws_mask(payload, mask = "\x37\xfa\x21\x3d".b)
  out = ''.b
  payload.bytes.each_with_index { |b, i| out << (b ^ mask.getbyte(i % 4)).chr }
  [mask, out]
end

# A client frame: FIN|opcode, MASK|len, mask, masked payload.
def ws_client_frame(opcode, payload, fin: true, len_override: nil, mask_bit: true)
  mask, masked = ws_mask(payload)
  head = ''.b
  head << ((fin ? 0x80 : 0x00) | opcode).chr
  n = len_override || payload.bytesize
  if n < 126
    head << ((mask_bit ? 0x80 : 0x00) | n).chr
  elsif n <= 0xffff
    head << ((mask_bit ? 0x80 : 0x00) | 126).chr
    head << ws_be16(n)
  else
    head << ((mask_bit ? 0x80 : 0x00) | 127).chr
    head << ws_be64(n)
  end
  head << mask if mask_bit
  head + (mask_bit ? masked : payload)
end

assert('ws: the accept key is RFC 6455 4.2.2 own example') do
  # The spec's worked example, verbatim: dGhlIHNhbXBsZSBub25jZQ== must
  # produce s3pPLMBiTxaQ9kYGzzhZRbK+xOo=.
  assert_equal 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=', WsVectors.accept_key('dGhlIHNhbXBsZSBub25jZQ==')
  # A key that is not 24 base64 characters is the client getting the
  # one thing it must get right wrong - refused, not hashed anyway.
  assert_nil WsVectors.accept_key('short')
  assert_nil WsVectors.accept_key('dGhlIHNhbXBsZSBub25jZQ=!')
end

assert('ws: a masked text frame unmasks to its payload (5.3)') do
  bytes = ws_client_frame(0x1, 'Hello')
  kind, opcode, fin, payload, consumed = WsVectors.parse(bytes)
  assert_equal :ok, kind
  assert_equal 0x1, opcode
  assert_true fin
  assert_equal 'Hello', payload
  assert_equal bytes.bytesize, consumed
end

assert('ws: a prefix asks for more, never a guess') do
  bytes = ws_client_frame(0x1, 'Hello')
  (bytes.bytesize - 1).times do |i|
    assert_equal [:need_more], WsVectors.parse(bytes[0, i]), "prefix of #{i} bytes"
  end
end

assert('ws: two frames in one buffer - consumed says where the second starts') do
  a = ws_client_frame(0x1, 'one')
  b = ws_client_frame(0x2, 'two')
  kind, _, _, payload, consumed = WsVectors.parse(a + b)
  assert_equal :ok, kind
  assert_equal 'one', payload
  assert_equal a.bytesize, consumed
  kind2, op2, _, payload2, = WsVectors.parse((a + b)[consumed..-1])
  assert_equal :ok, kind2
  assert_equal 0x2, op2
  assert_equal 'two', payload2
end

assert('ws: the refusals RFC 6455 5.1/5.2/5.5 name') do
  # 5.1: a client frame MUST be masked.
  kind, code = WsVectors.parse(ws_client_frame(0x1, 'x', mask_bit: false))
  assert_equal :error, kind
  assert_equal 1002, code

  # 5.2: RSV bits without a negotiated extension.
  rsv = ws_client_frame(0x1, 'x')
  rsv.setbyte(0, 0xc1)  # FIN | RSV1 | text
  assert_equal :error, WsVectors.parse(rsv)[0]

  # 5.2: reserved opcodes.
  [0x3, 0x7, 0xb, 0xf].each do |op|
    assert_equal :error, WsVectors.parse(ws_client_frame(op, 'x'))[0], "opcode #{op}"
  end

  # 5.5: a control frame is never fragmented and never over 125 bytes.
  assert_equal :error, WsVectors.parse(ws_client_frame(0x9, 'x', fin: false))[0]
  assert_equal :error, WsVectors.parse(ws_client_frame(0x9, 'y' * 126))[0]

  # 5.2: the length must use the minimal number of bytes - 126 spelled
  # as a 16-bit length that would have fit in 7 bits.
  nonminimal = ws_client_frame(0x1, 'x' * 100, len_override: 100)
  # rebuild by hand: 126 + a 16-bit 100
  hand = "\x81\xfe".b + ws_be16(100) + "\x37\xfa\x21\x3d".b + ws_mask('x' * 100)[1]
  assert_equal :error, WsVectors.parse(hand)[0]
  assert_equal :ok, WsVectors.parse(nonminimal)[0]

  # A payload past what this side will hold is 1009, not an allocation
  # the peer chose the size of.
  kind3, code3 = WsVectors.parse(ws_client_frame(0x2, 'z' * 200), 100)
  assert_equal :error, kind3
  assert_equal 1009, code3
end

assert('ws: a fragmented message keeps FIN and the continuation opcode') do
  first = ws_client_frame(0x1, 'Hel', fin: false)
  cont = ws_client_frame(0x0, 'lo', fin: true)
  k1, op1, fin1, p1, = WsVectors.parse(first)
  assert_equal [:ok, 0x1, false, 'Hel'], [k1, op1, fin1, p1]
  k2, op2, fin2, p2, = WsVectors.parse(cont)
  assert_equal [:ok, 0x0, true, 'lo'], [k2, op2, fin2, p2]
end

assert('ws: a server frame is never masked and spells the minimal length (5.1/5.2)') do
  assert_equal "\x81\x05".b, WsVectors.header(0x1, true, 5)
  assert_equal "\x01\x05".b, WsVectors.header(0x1, false, 5)
  assert_equal "\x82\x7e".b + ws_be16(126), WsVectors.header(0x2, true, 126)
  assert_equal "\x82\x7e".b + ws_be16(0xffff), WsVectors.header(0x2, true, 0xffff)
  big = WsVectors.header(0x2, true, 0x10000)
  assert_equal "\x82\x7f".b, big[0, 2]
  assert_equal 10, big.bytesize
  assert_equal ws_be64(0x10000), big[2, 8]
end

assert('ws: close payloads carry the code big-endian, the reason truncated (7.1.6)') do
  p = WsVectors.close_payload(1000, 'bye')
  assert_equal ws_be16(1000) + 'bye', p
  long = WsVectors.close_payload(1001, 'r' * 200)
  assert_equal 125, long.bytesize        # a control frame stays legal
  assert_equal ws_be16(1001), long[0, 2]

  code, reason = WsVectors.read_close(p)
  assert_equal 1000, code
  assert_equal 'bye', reason

  # 7.1.5: no payload is "no status", and it is not an error.
  code2, reason2 = WsVectors.read_close('')
  assert_equal 1005, code2
  assert_equal '', reason2

  # 7.1.6: one byte cannot be a code. 7.4.1: the local-only and
  # unassigned codes must never arrive on the wire.
  assert_nil WsVectors.read_close('x')
  [999, 1004, 1005, 1006, 1015, 1016, 2999].each do |c|
    assert_nil WsVectors.read_close(ws_be16(c)), "code #{c} must not be accepted"
  end
  [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1011, 3000, 4999].each do |c|
    assert_equal c, WsVectors.read_close(ws_be16(c))[0]
  end
end
