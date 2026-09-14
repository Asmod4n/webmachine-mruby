# The descriptor budget (src/ring_setup.hpp) and the count of open request
# body files (src/docroot.cpp), driven through Webmachine::SpecFd.
WM_FD = Webmachine::SpecFd unless defined?(WM_FD)

assert('fd: three quarters of the limit go to the rings, less the listener slots') do
  # RLIMIT_NOFILE belongs to the process, and a ring that took all of it
  # left nothing for the descriptors the process opens outside a ring
  # table - a request body in a file, a log, whatever an application
  # opens. Three quarters go to the rings; the last quarter stays.
  # (20000 / 4) * 3 - 16
  assert_equal 14_984, WM_FD.max_conns(20_000)
  # 16 listener slots come off the share, so the share has to pass them.
  # (21 / 4) * 3 = 15, which 16 takes whole; (23 / 4) * 3 = 15 as well,
  # and 24 is the first limit whose share is 18.
  assert_equal 0, WM_FD.max_conns(21)
  assert_equal 2, WM_FD.max_conns(24)
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
