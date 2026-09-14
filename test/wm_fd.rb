# The descriptor budget (src/ring_setup.hpp) and the count of open request
# body files (src/docroot.cpp), driven through Webmachine::SpecFd.
WM_FD = Webmachine::SpecFd unless defined?(WM_FD)

assert('fd: max_conns is the limit minus the reserve, the body files and the listeners') do
  # 20000 - 128 - 1024 - 16
  assert_equal 18_832, WM_FD.max_conns(20_000)
  # 1168 is taken whole; 1169 leaves one connection.
  assert_equal 0, WM_FD.max_conns(1168)
  assert_equal 1, WM_FD.max_conns(1169)
  # The fixed table stops at 2^20 entries, listeners included.
  assert_equal 1_048_560, WM_FD.max_conns(1 << 21)
end

# The count is process-wide for the whole mrbtest run. No other case
# opens a body file, so it starts at 0, and this case gives every slot
# back so it ends at 0 for whatever runs next.
assert('fd: the body file count refuses the slot at its ceiling and takes a give back') do
  assert_equal 0, WM_FD.body_files_open
  taken = 0
  taken += 1 while taken < 2000 && WM_FD.body_file_take
  assert_equal 1024, taken
  assert_false WM_FD.body_file_take
  assert_equal 1024, WM_FD.body_files_open
  WM_FD.body_file_give
  assert_equal 1023, WM_FD.body_files_open
  assert_true WM_FD.body_file_take
  1024.times { WM_FD.body_file_give }
  assert_equal 0, WM_FD.body_files_open
end
