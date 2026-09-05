#!/usr/bin/env ruby
# frozen_string_literal: true
#
# A WebSocket over HTTP/1.1 on one side, the same WebSocket over an
# HTTP/2 extended CONNECT (RFC 8441) on the other (#175).
#
# The Autobahn suite speaks RFC 6455 over HTTP/1.1 and nothing else. It
# has no HTTP/2 client, and neither has nghttpx, so the 500 cases that
# say whether a WebSocket is correct cannot reach our h2 path on their
# own. This bridge carries them: wstest connects here, this program
# opens ONE h2 connection per client, sends the extended CONNECT, and
# then moves bytes both ways without reading them. A WebSocket frame is
# opaque to the bridge, so every case that Autobahn can ask over h1 it
# asks over h2 as well.
#
#   tools/ws_h2_bridge.rb --listen 9978 --server 127.0.0.1:9977 --path /echo
#
# TWO LIMITS, and they are limits of the bridge, not of the server:
#
#  - permessage-deflate (cases 12.x and 13.x) is out. The bridge would
#    have to tell the client which extension the server took, and the
#    server's answer is HPACK with Huffman-coded values. A Huffman
#    decoder here would be a second HPACK implementation to keep
#    correct, so the bridge offers no extension at all and the h1 side
#    answers without one. bintest/h2.rb proves deflate over h2 instead,
#    by inflating what the server sends.
#  - The bridge is a test tool. It does not validate anything. What it
#    must get right is flow control (RFC 9113 6.9): it returns the
#    credit for every DATA byte it forwards, and it waits for credit
#    before it writes one. Autobahn case 9.x sends 16 MiB messages, so
#    both halves are load-bearing.
require 'socket'
require 'digest'
require 'base64'

DEFAULT_WINDOW = 65_535
MAX_FRAME = 16_384
PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b

def frame(type, flags, stream, payload = ''.b)
  len = payload.bytesize
  [(len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, type, flags].pack('C5') +
    [stream].pack('N') + payload
end

# HPACK, literal without indexing and never Huffman (RFC 7541 6.2.2).
# The bridge sends the smallest header block that is legal; it never
# has to decode one.
def hpack_literal(name, value)
  "\x00".b + name.bytesize.chr + name + value.bytesize.chr + value
end

def connect_block(path, authority)
  b = +''.b
  b << hpack_literal(':method', 'CONNECT')
  b << hpack_literal(':protocol', 'websocket')
  b << hpack_literal(':scheme', 'http')
  b << hpack_literal(':path', path)
  b << hpack_literal(':authority', authority)
  b
end

def read_exact(io, n)
  buf = +''.b
  buf << io.readpartial(n - buf.bytesize) while buf.bytesize < n
  buf
end

# The h1 side of the bridge: the RFC 6455 opening handshake, answered
# without any extension for the reason at the top of this file.
def h1_handshake(client)
  head = +''.b
  head << client.readpartial(1) until head.end_with?("\r\n\r\n")
  key = head[/^sec-websocket-key:\s*(\S+)/i, 1]
  raise 'no Sec-WebSocket-Key' unless key

  accept = Base64.strict_encode64(
    Digest::SHA1.digest(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
  )
  client.write("HTTP/1.1 101 Switching Protocols\r\n" \
               "Upgrade: websocket\r\nConnection: Upgrade\r\n" \
               "Sec-WebSocket-Accept: #{accept}\r\n\r\n")
  head[%r{^GET\s+(\S+)}, 1]
end

# One h2 connection, one stream, for the life of one WebSocket. The
# server is free to multiplex; the bridge is not, because a stream that
# shares a connection also shares the connection window with a peer that
# Autobahn does not know about.
def h2_open(host, port)
  up = TCPSocket.new(host, port)
  up.write(PREFACE + frame(4, 0, 0, ''.b))
  up
end

def parse_frame(up)
  h = read_exact(up, 9)
  len = (h.getbyte(0) << 16) | (h.getbyte(1) << 8) | h.getbyte(2)
  payload = len.positive? ? read_exact(up, len) : ''.b
  [h.getbyte(3), h.getbyte(4), h[5, 4].unpack1('N') & 0x7fff_ffff, payload]
end

def window_update(stream, n)
  frame(8, 0, stream, [n].pack('N'))
end

def serve(client, host, port, path, log)
  asked = h1_handshake(client)
  up = h2_open(host, port)
  up.write(frame(1, 0x04, 1, connect_block(path || asked, "#{host}:#{port}")))

  # What the peer lets us send, and what we still owe the peer.
  conn_send = DEFAULT_WINDOW
  strm_send = DEFAULT_WINDOW
  pending = +''.b     # client bytes that have no credit yet
  owed = 0            # forwarded DATA bytes whose credit is not returned

  loop do
    # The client is read only while the buffer has room: a peer that
    # gives no credit must not make the bridge grow without a bound.
    want = [up]
    want << client if pending.bytesize < (1 << 20)
    ready, = IO.select(want, nil, nil, 30)
    break unless ready

    if ready.include?(client)
      begin
        pending << client.readpartial(MAX_FRAME)
      rescue EOFError, IOError, Errno::ECONNRESET
        up.write(frame(0, 0x01, 1, ''.b)) rescue nil
        break
      end
    end

    if ready.include?(up)
      type, flags, stream, payload = parse_frame(up)
      case type
      when 0 # DATA - a WebSocket frame, or a piece of one
        client.write(payload) unless payload.empty?
        owed += payload.bytesize
        if owed >= DEFAULT_WINDOW / 2
          up.write(window_update(0, owed) + window_update(stream, owed))
          owed = 0
        end
        break if (flags & 0x01) != 0
      when 4 # SETTINGS
        if (flags & 0x01).zero?
          payload.bytes.each_slice(6) do |p|
            next unless ((p[0] << 8) | p[1]) == 0x4 # INITIAL_WINDOW_SIZE
            size = p[2..5].inject(0) { |a, b| (a << 8) | b }
            strm_send += size - DEFAULT_WINDOW
          end
          up.write(frame(4, 0x01, 0, ''.b))
        end
      when 6 # PING
        up.write(frame(6, 0x01, 0, payload)) if (flags & 0x01).zero?
      when 8 # WINDOW_UPDATE
        n = payload.unpack1('N') & 0x7fff_ffff
        if stream.zero? then conn_send += n else strm_send += n end
      when 3, 7 # RST_STREAM, GOAWAY
        break
      end
    end

    # Everything the credit covers, in frames the peer accepts.
    until pending.empty?
      room = [conn_send, strm_send, MAX_FRAME, pending.bytesize].min
      break if room <= 0

      up.write(frame(0, 0x00, 1, pending.byteslice(0, room)))
      pending = pending.byteslice(room, pending.bytesize - room) || +''.b
      conn_send -= room
      strm_send -= room
    end
  end
rescue StandardError => e
  log.puts("bridge: #{e.class}: #{e.message}")
ensure
  client.close rescue nil
  up&.close rescue nil
end

listen = 9978
server = '127.0.0.1:9977'
path = nil
argv = ARGV.dup
until argv.empty?
  case (a = argv.shift)
  when '--listen'  then listen = argv.shift.to_i
  when '--server'  then server = argv.shift
  when '--path'    then path = argv.shift
  else
    warn "usage: #{$PROGRAM_NAME} [--listen PORT] [--server HOST:PORT] [--path /echo]"
    warn "  saw: #{a}"
    exit 2
  end
end
host, port = server.split(':')

srv = TCPServer.new('127.0.0.1', listen)
$stdout.sync = true
puts "ws-h2 bridge: ws://127.0.0.1:#{listen} -> h2 #{server} (extended CONNECT)"
loop do
  client = srv.accept
  Thread.new(client) do |c|
    c.sync = true
    serve(c, host, port.to_i, path, $stdout)
  end
end
