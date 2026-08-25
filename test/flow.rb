
assert('flow: the shortcut agrees with the graph, exhaustively') do
  n = FlowVectors.sweep(0x9E3779B9, 12)
  assert_equal 16, FlowVectors::FACT_BITS
  assert_equal (7 + 12) * 7 * (1 << 16), n
  true
end

assert('flow: what the default resource decides at bind time') do
  get, head = FlowVectors.default_shortcut(0), FlowVectors.default_shortcut(1)
  assert_equal [200, false], get
  assert_equal [200, false], head

  [2, 3, 4, 5].each do |m|
    assert_equal [405, true], FlowVectors.default_shortcut(m)
  end
  assert_equal [501, true], FlowVectors.default_shortcut(6)
  true
end
