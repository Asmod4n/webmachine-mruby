# The one thing a HAL is for: a task that never yields must still lose
# the CPU. Two of them with no yield anywhere have to interleave, which
# only the ticker thread can make happen.
assert('hal: a CPU-bound task is preempted') do
  order = []
  Task.new(name: 'a') { 6.times { order << 'a'; j = 0; j += 1 while j < 1_500_000 } }
  Task.new(name: 'b') { 6.times { order << 'b'; j = 0; j += 1 while j < 1_500_000 } }
  Task.run
  assert_equal 12, order.size
  switches = 0
  order.each_with_index { |x, i| switches += 1 if i > 0 && order[i - 1] != x }
  assert_true switches > 1, "no preemption: #{order.join(' ')}"
end

assert('hal: a sleeping task wakes, and the ticker was parked meanwhile') do
  $hal_woke = false
  Task.new(name: 'sleeper') { sleep_ms(30); $hal_woke = true }
  Task.run
  assert_true $hal_woke
end

