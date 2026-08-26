
# The asset tier's decision for one request, without a socket, a ZIP or a
# server. RFC 9110 14.1/14.2 is a table, so it gets one.
AV = AssetVectors
# An asset's ETag is fixed width: AssetEntry::etag is char[10] and the
# If-Range comparison is exactly those ten bytes.
ETAG = '"abcd1234"'.freeze
WIRE = 1000

def av(verdict: 200, head_only: false, method: AV::GET, range: '', if_range: nil,
       etag: ETAG, budget: 64 * 1024, wire: WIRE)
  head, status, off, len, body, copy =
    AV.step(wire, verdict, head_only ? 1 : 0, method, range, if_range, etag, budget)
  { head: head, status: status, off: off, len: len, body: body, copy: copy }
end

assert('asset_step: no range asked, the whole representation goes out') do
  r = av
  assert_equal AV::NORMAL, r[:head]
  assert_equal 200, r[:status]
  assert_equal 0, r[:off]
  assert_equal WIRE, r[:len]
  assert_true r[:body]
  assert_true r[:copy]
  true
end

assert('asset_step: HEAD names the length and sends no bytes') do
  r = av(head_only: true)
  assert_equal AV::NORMAL, r[:head]
  assert_equal 200, r[:status]
  assert_false r[:body]
  assert_equal 0, r[:len]
  # And a Range on a HEAD is not a 206 either.
  r2 = av(head_only: true, range: 'bytes=0-9')
  assert_equal AV::NORMAL, r2[:head]
  assert_false r2[:body]
  true
end

assert('asset_step: a range is honoured only where RFC 9110 14.2 allows it') do
  r = av(range: 'bytes=0-9')
  assert_equal AV::RANGE, r[:head]
  assert_equal 206, r[:status]
  assert_equal 0, r[:off]
  assert_equal 10, r[:len]
  assert_true r[:body]

  # Not on a method that is not GET.
  assert_equal AV::NORMAL, av(range: 'bytes=0-9', method: AV::POST)[:head]
  # Not on an answer that would not have been a 200.
  assert_equal AV::NORMAL, av(range: 'bytes=0-9', verdict: 304)[:head]
  # Not when If-Range names a different representation.
  assert_equal AV::NORMAL, av(range: 'bytes=0-9', if_range: '"other"')[:head]
  # But yes when If-Range still matches.
  assert_equal AV::RANGE, av(range: 'bytes=0-9', if_range: ETAG)[:head]
  true
end

assert('asset_step: a range past the end is 416 and carries no body') do
  r = av(range: "bytes=#{WIRE + 5}-")
  assert_equal AV::UNSAT, r[:head]
  assert_equal 416, r[:status]
  assert_false r[:body]
  assert_equal 0, r[:len]
  true
end

assert('asset_step: a suffix range ends at the last byte') do
  r = av(range: 'bytes=990-')
  assert_equal AV::RANGE, r[:head]
  assert_equal 990, r[:off]
  assert_equal 10, r[:len]
  assert_true r[:off] + r[:len] <= WIRE, 'never past the representation'
  true
end

assert('asset_step: a refusal spells a status head and nothing else') do
  [412, 501].each do |code|
    r = av(verdict: code)
    assert_equal AV::REFUSAL, r[:head], "verdict #{code}"
    assert_equal code, r[:status]
    assert_false r[:body]
    assert_equal 0, r[:len]
  end
  true
end

# The copy/lend threshold is a [tune] knob, so where it flips is a contract.
assert('asset_step: copy below the warm budget, lend at and above it') do
  assert_true  av(wire: 100, budget: 100)[:copy]
  assert_false av(wire: 101, budget: 100)[:copy]
  assert_true  av(wire: 4096, budget: 0)[:body]
  assert_false av(wire: 4096, budget: 0)[:copy], 'budget 0 lends everything'
  true
end
