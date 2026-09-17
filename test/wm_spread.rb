##
## Which answering thread a peer meets, driven through
## Webmachine::SpecSpread. The acceptor keeps no table: it reads the
## peer's name and derives the thread from it, so the same name always
## meets the same thread and nothing is remembered between connections.
##
## What these pin is that the derivation spreads. The mix this replaced
## was FNV-1a, whose last step is a multiply, so the low bits that
## `% nworkers` reads carried the input rather than a mix of it. Two pids
## an even distance apart then met the same thread almost always, which
## left half of a two-thread server unused.
##
WM_SPREAD = Webmachine::SpecSpread unless defined?(WM_SPREAD)

def spread_pid(pid)
  [pid].pack('V')
end

# The share of the ideal count that the least used thread receives.
# A perfect spread answers 1.0. A sample of a few hundred names varies
# around the ideal by itself, so a healthy mix answers about 0.7 here,
# and the defect this replaced answered almost 0: one thread of two
# received nothing.
def spread_floor(names, nworkers)
  seen = Array.new(nworkers, 0)
  names.each { |n| seen[WM_SPREAD.worker_of(n, nworkers)] += 1 }
  ideal = names.size.to_f / nworkers
  seen.min / ideal
end

assert('spread: the same name always answers the same thread') do
  name = spread_pid(4242)
  [2, 3, 8, 64].each do |n|
    first = WM_SPREAD.worker_of(name, n)
    20.times { assert_equal first, WM_SPREAD.worker_of(name, n) }
  end
end

assert('spread: the answer is inside the thread count') do
  [1, 2, 3, 7, 8, 64].each do |n|
    (1000..1200).each do |pid|
      w = WM_SPREAD.worker_of(spread_pid(pid), n)
      assert_true w >= 0 && w < n, "nworkers=#{n} pid=#{pid} answered #{w}"
    end
  end
end

assert('spread: one thread takes everything') do
  (1..50).each { |pid| assert_equal 0, WM_SPREAD.worker_of(spread_pid(pid), 1) }
end

# The case that was broken. Pids come out of the kernel in a run, and a
# client fleet is a handful of them. Every distance has to spread, not
# only the odd ones.
assert('spread: consecutive pids fill every thread') do
  [2, 4, 8].each do |n|
    (1..8).each do |gap|
      names = []
      512.times { |i| names << spread_pid(1000 + i * gap) }
      floor = spread_floor(names, n)
      assert_true floor > 0.5, "nworkers=#{n} gap=#{gap}: the quietest thread took #{(floor * 100).round(1)}% of its share"
    end
  end
end

assert('spread: client addresses fill every thread') do
  [2, 4, 8].each do |n|
    v4 = (0...256).map { |i| [203, 0, 113, i].pack('C4') }
    floor = spread_floor(v4, n)
    assert_true floor > 0.5, "a /24 over #{n} threads: the quietest took #{(floor * 100).round(1)}% of its share"
  end
end

assert('spread: an IPv6 address answers too') do
  name = ([0x20, 0x01, 0x0d, 0xb8] + Array.new(12, 0)).pack('C16')
  [2, 8].each { |n| assert_true WM_SPREAD.worker_of(name, n) < n }
end

assert('spread: a name of any length answers') do
  [1, 2, 3, 5, 7, 9].each do |len|
    name = 'x' * len
    [2, 8].each { |n| assert_true WM_SPREAD.worker_of(name, n) < n }
  end
end

assert('spread: a thread count of zero is refused') do
  assert_raise(ArgumentError) { WM_SPREAD.worker_of(spread_pid(1), 0) }
end
