
def hx(s)
  hex = ''
  i = 0
  while i < s.length
    c = s[i]
    hex << c unless c == ' ' || c == "\n"
    i += 1
  end
  out = ''
  i = 0
  while i < hex.length
    out << hex[i, 2].to_i(16).chr
    i += 2
  end
  out
end

assert('hpack: RFC 7541 C.3 - three requests, no Huffman, one dynamic table') do
  got = HPackVectors.decode_blocks([
    hx('8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d'),
    hx('8286 84be 5808 6e6f 2d63 6163 6865'),
    hx('8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65')
  ])
  assert_equal [[':method', 'GET'], [':scheme', 'http'], [':path', '/'],
                [':authority', 'www.example.com']], got[0]
  assert_equal [[':method', 'GET'], [':scheme', 'http'], [':path', '/'],
                [':authority', 'www.example.com'], ['cache-control', 'no-cache']], got[1]
  assert_equal [[':method', 'GET'], [':scheme', 'https'], [':path', '/index.html'],
                [':authority', 'www.example.com'], ['custom-key', 'custom-value']], got[2]
end

assert('hpack: RFC 7541 C.4 - the same three requests, Huffman-coded') do
  got = HPackVectors.decode_blocks([
    hx('8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff'),
    hx('8286 84be 5886 a8eb 1064 9cbf'),
    hx('8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf')
  ])
  assert_equal [[':method', 'GET'], [':scheme', 'http'], [':path', '/'],
                [':authority', 'www.example.com']], got[0]
  assert_equal [[':method', 'GET'], [':scheme', 'http'], [':path', '/'],
                [':authority', 'www.example.com'], ['cache-control', 'no-cache']], got[1]
  assert_equal [[':method', 'GET'], [':scheme', 'https'], [':path', '/index.html'],
                [':authority', 'www.example.com'], ['custom-key', 'custom-value']], got[2]
end

assert('hpack: roundtrip keeps every byte, tables live across blocks') do
  blocks = [
    [[':method', 'GET'], [':scheme', 'https'], [':path', '/kept'],
     [':authority', 'example.com'], ['x-probe', 'hello world']],
    [[':method', 'GET'], [':scheme', 'https'], [':path', '/kept'],
     [':authority', 'example.com'], ['x-probe', 'hello world']],
    [[':method', 'POST'], [':path', '/kept?x=1&y=2'],
     ['x-probe', "\x00\x01\xfe\xff binary"], ['cookie', 'a=' + ('z' * 512)]]
  ]
  assert_equal blocks, HPackVectors.roundtrip_blocks(blocks)
end

assert('hpack: roundtrip survives a 256-byte table, evictions included') do
  blocks = (1..6).map do |i|
    [[':status', '200'], ['cache-control', 'private'],
     ['set-cookie', "s=#{i.to_s * 60}"]]
  end
  assert_equal blocks, HPackVectors.roundtrip_blocks(blocks, 256)
end
