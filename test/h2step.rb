
# RFC 9113 6.9.1 as a table: which window binds, how much may go out, and
# when END_STREAM rides along. None of this needed a peer to check.
HV = H2Vectors

def hv(kind, start: 0, total: 1000, swin: 65_535, cwin: 65_535, chunk: HV::CHUNK)
  src, st, give, tot, ends = HV.step(kind, start, total, swin, cwin, chunk)
  { src: src, start: st, give: give, total: tot, ends: ends }
end

assert('h2_send_step: a stream with nothing to send names no source') do
  r = hv(HV::NONE)
  assert_equal HV::NONE, r[:src]
  assert_equal 0, r[:give]
  assert_false r[:ends]
  true
end

assert('h2_send_step: the smaller of the two windows binds') do
  assert_equal 300, hv(HV::LENT, total: 1000, swin: 300, cwin: 900)[:give]
  assert_equal 400, hv(HV::LENT, total: 1000, swin: 900, cwin: 400)[:give]
  # and never more than what is left of the body
  assert_equal 1000, hv(HV::LENT, total: 1000, swin: 65_535, cwin: 65_535)[:give]
  assert_equal 250,  hv(HV::LENT, start: 750, total: 1000)[:give]
  true
end

# The bug this shape prevents: a source is chosen FIRST, then the window is
# consulted. A stream whose window is shut must send nothing at all - not
# fall through and send from a different source.
assert('h2_send_step: a shut window sends nothing and does not fall through') do
  [[HV::ASSET, HV::ASSET], [HV::LENT, HV::LENT], [HV::PENDING, HV::PENDING]].each do |kind, want|
    [[0, 65_535], [65_535, 0], [-5, 65_535], [65_535, -5]].each do |swin, cwin|
      r = hv(kind, swin: swin, cwin: cwin)
      assert_equal want, r[:src], "kind #{kind}, windows #{swin}/#{cwin}: source still named"
      assert_equal 0, r[:give], "kind #{kind}, windows #{swin}/#{cwin}: nothing may go"
      assert_false r[:ends]
    end
  end
  true
end

assert('h2_send_step: END_STREAM rides the round that reaches the last byte') do
  assert_true  hv(HV::LENT, start: 0, total: 1000)[:ends]
  assert_true  hv(HV::LENT, start: 900, total: 1000)[:ends]
  # cut by a window: the body is not finished, so nothing ends
  assert_false hv(HV::LENT, start: 0, total: 1000, swin: 999)[:ends]
  assert_false hv(HV::LENT, start: 0, total: 1000, cwin: 1)[:ends]
  # a round that may send nothing never ends a stream either
  assert_false hv(HV::LENT, start: 0, total: 1000, swin: 0)[:ends]
  true
end

assert('h2_send_step: a copied buffer is bounded per round, a lend is not') do
  big = HV::CHUNK * 3
  # pending: capped at the delivery chunk, so it takes several rounds
  p = hv(HV::PENDING, total: big, swin: 1 << 30, cwin: 1 << 30)
  assert_equal HV::CHUNK, p[:give]
  assert_false p[:ends], 'a capped round cannot be the last one'
  # a lend and a mapping are bounded only by the windows
  assert_equal big, hv(HV::LENT, total: big, swin: 1 << 30, cwin: 1 << 30)[:give]
  assert_equal big, hv(HV::ASSET, total: big, swin: 1 << 30, cwin: 1 << 30)[:give]
  true
end

assert('h2_send_step: give never runs past the body, whatever the windows') do
  [1, 7, 1000, HV::CHUNK - 1, HV::CHUNK, HV::CHUNK + 1].each do |total|
    [0, 1, total / 2, total].each do |start|
      [1, 13, 65_535, 1 << 30].each do |win|
        r = hv(HV::LENT, start: start, total: total, swin: win, cwin: win)
        assert_true r[:start] + r[:give] <= total, "start #{start} give #{r[:give]} total #{total}"
        assert_true r[:give] <= win, "give #{r[:give]} exceeds window #{win}"
        assert_equal (r[:start] + r[:give] == total && r[:give] > 0), r[:ends]
      end
    end
  end
  true
end
