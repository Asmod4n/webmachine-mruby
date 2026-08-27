
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
  assert_equal 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=', WsVectors.accept_key('dGhlIHNhbXBsZSBub25jZQ==')
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
  kind, code = WsVectors.parse(ws_client_frame(0x1, 'x', mask_bit: false))
  assert_equal :error, kind
  assert_equal 1002, code

  rsv = ws_client_frame(0x1, 'x')
  rsv.setbyte(0, 0xc1)
  assert_equal :error, WsVectors.parse(rsv)[0]

  [0x3, 0x7, 0xb, 0xf].each do |op|
    assert_equal :error, WsVectors.parse(ws_client_frame(op, 'x'))[0], "opcode #{op}"
  end

  assert_equal :error, WsVectors.parse(ws_client_frame(0x9, 'x', fin: false))[0]
  assert_equal :error, WsVectors.parse(ws_client_frame(0x9, 'y' * 126))[0]

  nonminimal = ws_client_frame(0x1, 'x' * 100, len_override: 100)
  hand = "\x81\xfe".b + ws_be16(100) + "\x37\xfa\x21\x3d".b + ws_mask('x' * 100)[1]
  assert_equal :error, WsVectors.parse(hand)[0]
  assert_equal :ok, WsVectors.parse(nonminimal)[0]

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
  assert_equal 125, long.bytesize
  assert_equal ws_be16(1001), long[0, 2]

  code, reason = WsVectors.read_close(p)
  assert_equal 1000, code
  assert_equal 'bye', reason

  code2, reason2 = WsVectors.read_close('')
  assert_equal 1005, code2
  assert_equal '', reason2

  assert_nil WsVectors.read_close('x')
  [999, 1004, 1005, 1006, 1015, 1016, 2999].each do |c|
    assert_nil WsVectors.read_close(ws_be16(c)), "code #{c} must not be accepted"
  end
  [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1011, 3000, 4999].each do |c|
    assert_equal c, WsVectors.read_close(ws_be16(c))[0]
  end
end


def ws_neg(offer)
  WsVectors.negotiate(offer)
end

assert('ws: a bare permessage-deflate offer is accepted bare (7692 5.1)') do
  answer, snct, cnct, sbits, cbits = ws_neg('permessage-deflate')
  assert_equal 'permessage-deflate', answer
  assert_false snct
  assert_false cnct
  assert_equal [15, 15], [sbits, cbits]
end

assert('ws: an extension this endpoint does not offer is declined, not failed') do
  assert_nil ws_neg('x-webkit-deflate-frame')
  assert_nil ws_neg('')
  assert_nil ws_neg('permessage-deflate; nonsense_parameter')
  assert_nil ws_neg('permessage-deflate; server_no_context_takeover=1')
  assert_nil ws_neg('permessage-deflate; server_max_window_bits')
  assert_nil ws_neg('permessage-deflate; server_max_window_bits=16')
  assert_nil ws_neg('permessage-deflate; server_max_window_bits=08')
  assert_nil ws_neg('permessage-deflate; client_max_window_bits=7')
  assert_nil ws_neg('permessage-deflate; server_no_context_takeover; server_no_context_takeover')
end

assert('ws: the first acceptable offer in the list wins (7692 5.1)') do
  answer, snct = ws_neg('permessage-deflate; unknown_thing, permessage-deflate; ' \
                        'server_no_context_takeover')
  assert_equal 'permessage-deflate; server_no_context_takeover', answer
  assert_true snct
  answer2, = ws_neg('mux; max-channels=4, permessage-deflate')
  assert_equal 'permessage-deflate', answer2
end

assert('ws: no_context_takeover is echoed as confirmation (7692 7.1.1)') do
  answer, snct, cnct = ws_neg('permessage-deflate; client_no_context_takeover; ' \
                              'server_no_context_takeover')
  assert_equal 'permessage-deflate; server_no_context_takeover; client_no_context_takeover',
               answer
  assert_true snct
  assert_true cnct
end

assert('ws: server_max_window_bits is echoed, and 8 is declined by name (7692 7.1.2.1)') do
  answer, _, _, sbits = ws_neg('permessage-deflate; server_max_window_bits=10')
  assert_equal 'permessage-deflate; server_max_window_bits=10', answer
  assert_equal 10, sbits
  answer15, _, _, sbits15 = ws_neg('permessage-deflate; server_max_window_bits=15')
  assert_equal 'permessage-deflate; server_max_window_bits=15', answer15
  assert_equal 15, sbits15
  assert_nil ws_neg('permessage-deflate; server_max_window_bits=8')
  answer8, = ws_neg('permessage-deflate; server_max_window_bits=8, permessage-deflate')
  assert_equal 'permessage-deflate', answer8
end

assert('ws: client_max_window_bits is echoed only when it carried one (7692 7.1.2.2)') do
  answer, _, _, _, cbits = ws_neg('permessage-deflate; client_max_window_bits')
  assert_equal 'permessage-deflate', answer
  assert_equal 15, cbits
  answer9, _, _, _, cbits9 = ws_neg('permessage-deflate; client_max_window_bits=9')
  assert_equal 'permessage-deflate; client_max_window_bits=9', answer9
  assert_equal 9, cbits9
end

assert('ws: client_max_window_bits=8 is taken at its word, 9 bits wide (zlib)') do
  answer, _, _, _, cbits = ws_neg('permessage-deflate; client_max_window_bits=8')
  assert_equal 'permessage-deflate; client_max_window_bits=8', answer
  assert_equal 8, cbits
end

assert('ws: a quoted parameter value is the same value (9110 5.6.4)') do
  answer, _, _, sbits = ws_neg('permessage-deflate; server_max_window_bits="12"')
  assert_equal 'permessage-deflate; server_max_window_bits=12', answer
  assert_equal 12, sbits
end

assert('ws: whitespace and a trailing comma are list syntax, not content') do
  answer, snct = ws_neg("  permessage-deflate ;  server_no_context_takeover  ,  ")
  assert_equal 'permessage-deflate; server_no_context_takeover', answer
  assert_true snct
end

assert('ws: RSV1 is legal exactly when permessage-deflate was negotiated (7692 6)') do
  frame = ws_client_frame(0x1, 'x')
  frame.setbyte(0, 0xc1)
  assert_equal :error, WsVectors.parse(frame)[0]
  kind, opcode, fin, payload, _, rsv1 = WsVectors.parse(frame, 1 << 20, true)
  assert_equal [:ok, 0x1, true, 'x', true], [kind, opcode, fin, payload, rsv1]
  assert_false WsVectors.parse(ws_client_frame(0x1, 'x'), 1 << 20, true)[5]

  cont = ws_client_frame(0x0, 'x')
  cont.setbyte(0, 0xc0)
  assert_equal :error, WsVectors.parse(cont, 1 << 20, true)[0]
  ping = ws_client_frame(0x9, 'x')
  ping.setbyte(0, 0xc9)
  assert_equal :error, WsVectors.parse(ping, 1 << 20, true)[0]

  [0xa1, 0x91].each do |b0|
    other = ws_client_frame(0x1, 'x')
    other.setbyte(0, b0)
    assert_equal :error, WsVectors.parse(other, 1 << 20, true)[0], "b0 #{b0}"
  end
end

assert('ws: a server frame carries RSV1 only when asked to (7692 6)') do
  assert_equal "\xc1\x05".b, WsVectors.header(0x1, true, 5, true)
  assert_equal "\x81\x05".b, WsVectors.header(0x1, true, 5, false)
  assert_equal "\x41\x05".b, WsVectors.header(0x1, false, 5, true)
end

# RFC 6455 5.2 as a table: the fourteen header bytes, judged on their own.
# These are the Autobahn cases, and until now none of them had a unit test -
# begin_frame judged one rule at a time while writing the refusal.
WS_NONE = 0
WS_PROTO = 1
WS_TOOBIG = 2

# A masked frame header: fin/rsv1/opcode, then the length encoding, then
# four mask bytes.
def ws_head_bytes(opcode, fin: true, rsv1: false, rsv23: 0, masked: true, len: 0, force: nil)
  b0 = (fin ? 0x80 : 0) | (rsv1 ? 0x40 : 0) | (rsv23 << 4) | opcode
  n = force || (len < 126 ? len : (len <= 0xffff ? 126 : 127))
  out = b0.chr + ((masked ? 0x80 : 0) | n).chr
  out += ws_be16(len) if n == 126
  out += ws_be64(len) if n == 127
  out + "\x01\x02\x03\x04"
end

assert('ws head: a well-formed masked frame is accepted') do
  err, opcode, plen, mask_at, fin, rsv1, control = WsVectors.head(ws_head_bytes(0x1, len: 5))
  assert_equal WS_NONE, err
  assert_equal 0x1, opcode
  assert_equal 5, plen
  assert_equal 2, mask_at
  assert_true fin
  assert_false rsv1
  assert_false control
  true
end

assert('ws head: RFC 6455 5.2 - reserved bits, opcodes and the mask bit') do
  # RSV2/RSV3 are never negotiated here
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x1, rsv23: 1))[0]
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x1, rsv23: 2))[0]
  # RSV1 only where a codec was negotiated
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x1, rsv1: true), false)[0]
  assert_equal WS_NONE,  WsVectors.head(ws_head_bytes(0x1, rsv1: true), true)[0]
  # and never on a control frame or a continuation, codec or not
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x9, rsv1: true), true)[0]
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x0, rsv1: true), true)[0]
  # unknown opcodes
  [0x3, 0x7, 0xb, 0xf].each do |op|
    assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(op))[0], "opcode #{op}"
  end
  # a client frame is always masked
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x1, masked: false))[0]
  true
end

assert('ws head: the length must use its shortest encoding') do
  # 126 announced but a value that fits in seven bits
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x1, len: 5, force: 126))[0]
  assert_equal WS_NONE,  WsVectors.head(ws_head_bytes(0x1, len: 126))[0]
  # 127 announced but a value that fits in sixteen bits
  assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(0x1, len: 1000, force: 127))[0]
  assert_equal WS_NONE,  WsVectors.head(ws_head_bytes(0x1, len: 70_000))[0]
  # the mask sits after the length field, wherever that ends
  assert_equal 2,  WsVectors.head(ws_head_bytes(0x1, len: 5))[3]
  assert_equal 4,  WsVectors.head(ws_head_bytes(0x1, len: 126))[3]
  assert_equal 10, WsVectors.head(ws_head_bytes(0x1, len: 70_000))[3]
  true
end

assert('ws head: RFC 6455 5.5 - a control frame is short and never split') do
  [0x8, 0x9, 0xa].each do |op|
    assert_equal WS_NONE,  WsVectors.head(ws_head_bytes(op, len: 125))[0], "opcode #{op}"
    assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(op, len: 126))[0], "opcode #{op} too long"
    assert_equal WS_PROTO, WsVectors.head(ws_head_bytes(op, fin: false))[0], "opcode #{op} split"
    assert_true WsVectors.head(ws_head_bytes(op))[6], "opcode #{op} is a control frame"
  end
  true
end

assert('ws admit: RFC 6455 5.4 - a message is one at a time') do
  max = 1 << 20
  # a continuation that continues nothing
  assert_equal WS_PROTO, WsVectors.admit(ws_head_bytes(0x0), max, 0)
  # a continuation while a text message is open
  assert_equal WS_NONE,  WsVectors.admit(ws_head_bytes(0x0), max, 0x1)
  # a second data frame while one is open
  assert_equal WS_PROTO, WsVectors.admit(ws_head_bytes(0x1), max, 0x1)
  assert_equal WS_PROTO, WsVectors.admit(ws_head_bytes(0x2), max, 0x1)
  # a control frame may always interleave
  [0x8, 0x9, 0xa].each do |op|
    assert_equal WS_NONE, WsVectors.admit(ws_head_bytes(op), max, 0x1), "control #{op}"
  end
  true
end

assert('ws admit: RFC 6455 7.4.1 - 1009 when the message would run past max') do
  max = 1000
  assert_equal WS_NONE,   WsVectors.admit(ws_head_bytes(0x1, len: 1000), max, 0)
  assert_equal WS_TOOBIG, WsVectors.admit(ws_head_bytes(0x1, len: 1001), max, 0)
  # a continuation counts what is already collected
  assert_equal WS_NONE,   WsVectors.admit(ws_head_bytes(0x0, len: 400), max, 0x1, false, 600)
  assert_equal WS_TOOBIG, WsVectors.admit(ws_head_bytes(0x0, len: 401), max, 0x1, false, 600)
  # a deflated message is bounded after inflation, not here
  assert_equal WS_NONE, WsVectors.admit(ws_head_bytes(0x1, rsv1: true, len: 5000), max,
                                        0, false, 0, true)
  assert_equal WS_NONE, WsVectors.admit(ws_head_bytes(0x0, len: 5000), max, 0x1, true, 600)
  true
end
