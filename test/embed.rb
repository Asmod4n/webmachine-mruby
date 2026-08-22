# The flow machine driven with no IO at all: request bytes in, response
# bytes out, compared byte for byte. What bintest/http1.rb proves over a
# real socket is proven here over a std::string - which is the point of
# src/embed.hpp. Both suites pass, so neither layer needs the other to
# run, and that is the cut stated as a test.
#
# The date is the only part of a response not fixed at build time, and
# it sits at a KNOWN offset (that is how the writer patches it in
# place), so it is stepped over by length rather than matched. No
# Regexp in this build, and none is needed for an offset.

WM_OK_HEAD = "HTTP/1.1 200 OK\r\nDate: "
WM_OK_TAIL = "\r\nContent-Length: 2\r\n\r\nOK"
WM_OK_LEN = WM_OK_HEAD.size + EmbedVectors::DATE_LEN + WM_OK_TAIL.size

# One response starting at `at`: everything before the date, the date
# itself, everything the caller still has to look at.
def wm_cut(resp, at)
  from = at + WM_OK_HEAD.size
  [resp[at, WM_OK_HEAD.size], resp[from, EmbedVectors::DATE_LEN],
   resp[from + EmbedVectors::DATE_LEN, resp.size]]
end

assert('embed: a whole request in, the whole response out, no socket') do
  resp, open = EmbedVectors.exchange(["GET / HTTP/1.1\r\nHost: x\r\n\r\n"])
  assert_equal WM_OK_LEN, resp.size
  head, date, tail = wm_cut(resp, 0)
  assert_equal WM_OK_HEAD, head
  assert_equal WM_OK_TAIL, tail
  # IMF-fixdate, RFC 9110 5.6.7: "Sun, 06 Nov 1994 08:49:37 GMT".
  assert_equal 29, date.size
  assert_equal ', ', date[3, 2]
  assert_equal ' GMT', date[25, 4]
  # 1.1 persists unless told otherwise (RFC 9112 9.3): still open.
  assert_true open
  true
end

assert('embed: a head trickled byte by byte parses the same') do
  # The carry path: every chunk but the last ends mid-head, so the
  # facade hands each one over and gets nothing back until the head is
  # complete. Same bytes out as the single-chunk exchange above.
  req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
  chunks = []
  i = 0
  while i < req.size
    chunks << req[i, 1]
    i += 1
  end
  resp, open = EmbedVectors.exchange(chunks)
  assert_equal WM_OK_LEN, resp.size
  head, _, tail = wm_cut(resp, 0)
  assert_equal WM_OK_HEAD, head
  assert_equal WM_OK_TAIL, tail
  assert_true open
  true
end

assert('embed: pipelined requests answer in order, out of one feed') do
  resp, open = EmbedVectors.exchange(["GET /a HTTP/1.1\r\nHost: x\r\n\r\n" * 3])
  assert_equal WM_OK_LEN * 3, resp.size
  3.times do |n|
    head, _, _ = wm_cut(resp, n * WM_OK_LEN)
    assert_equal WM_OK_HEAD, head
    assert_equal WM_OK_TAIL, resp[n * WM_OK_LEN + WM_OK_HEAD.size + EmbedVectors::DATE_LEN,
                                  WM_OK_TAIL.size]
  end
  assert_true open
  true
end

assert('embed: a body is skipped and the framing survives it') do
  # The default resource allows GET/HEAD only, so POST konsts to 405 at
  # B10 (RFC 9110 15.5.6) - but its body must still be consumed, or the
  # GET behind it would be parsed out of body bytes.
  head405 = "HTTP/1.1 405 Method Not Allowed\r\nDate: "
  tail405 = "\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\n\r\n"
  len405 = head405.size + EmbedVectors::DATE_LEN + tail405.size
  resp, open = EmbedVectors.exchange(
    ["POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
     "GET / HTTP/1.1\r\nHost: x\r\n\r\n"]
  )
  assert_equal len405 + WM_OK_LEN, resp.size
  assert_equal head405, resp[0, head405.size]
  assert_equal tail405, resp[head405.size + EmbedVectors::DATE_LEN, tail405.size]
  head, _, tail = wm_cut(resp, len405)
  assert_equal WM_OK_HEAD, head
  assert_equal WM_OK_TAIL, tail
  assert_true open
  true
end

assert('embed: Connection: close is answered, then the connection ends') do
  resp, open = EmbedVectors.exchange(["GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"])
  head, _, tail = wm_cut(resp, 0)
  assert_equal WM_OK_HEAD, head
  assert_equal "\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOK", tail
  # False is the facade's whole close story: nothing is closed here,
  # because nothing was ever opened. That belongs to whoever owns the
  # bytes.
  assert_false open
  true
end

assert('embed: a malformed head is refused by name, and the machine says so') do
  # A header line with no colon is not a head (RFC 9112 2.2): 400, and
  # framing trust is gone, so the connection ends with it.
  refused = "HTTP/1.1 400 Bad Request\r\nDate: "
  resp, open = EmbedVectors.exchange(["GET / HTTP/1.1\r\nHost x\r\n\r\n"])
  assert_equal refused, resp[0, refused.size]
  assert_equal "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
               resp[refused.size + EmbedVectors::DATE_LEN, resp.size]
  assert_false open
  true
end
