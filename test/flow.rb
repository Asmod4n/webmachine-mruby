# The shortcut that keeps the flow machine from running must never give
# an answer the machine would not have given. Everything else in this
# file is commentary; that sentence is the test.
#
# flow::answer skips the graph on two grounds. One is sound by
# construction - `plain` means the facts ARE the ones the precomputed
# status was walked with, so it is the same walk. The other, `always`,
# is a claim: that no reachable node reads the request at all. A wrong
# claim there would hand a conditional request the unconditional
# answer, silently, on one resource, for one method - the kind of bug
# that survives every hand-written case. So it is brute-forced.

assert('flow: the shortcut agrees with the graph, exhaustively') do
  # 7 methods x 2^16 fact combinations, against the default resource's
  # vectors and against random ones - vectors no resource compiles to,
  # which is exactly why they are here: `always` is a statement about
  # the graph, not about plausible resources.
  n = FlowVectors.sweep(0x9E3779B9, 12)
  assert_equal 16, FlowVectors::FACT_BITS
  assert_equal (7 + 12) * 7 * (1 << 16), n
  true
end

assert('flow: what the default resource decides at bind time') do
  # The measurement this whole shortcut was built from: on a resource
  # that overrides nothing, only GET and HEAD have anything left to
  # decide per request. The rest re-derive a fixed status from facts
  # that cannot change it - 4 node visits for a 405, 2 for a 501.
  get, head = FlowVectors.default_shortcut(0), FlowVectors.default_shortcut(1)
  assert_equal [200, false], get
  assert_equal [200, false], head

  # allowed_methods defaults to GET/HEAD, so these die at B10 before a
  # single request-dependent node is reachable (RFC 9110 15.5.6).
  [2, 3, 4, 5].each do |m|  # POST, PUT, DELETE, OPTIONS
    assert_equal [405, true], FlowVectors.default_shortcut(m)
  end
  # An unrecognised method dies one node earlier still, at B12 (15.6.2).
  assert_equal [501, true], FlowVectors.default_shortcut(6)
  true
end
