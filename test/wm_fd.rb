# The count of open request body files (src/docroot.cpp), driven through
# Webmachine::SpecFd.
#
# Two numbers used to be pinned here and neither exists now. How many
# peers a ring holds is RLIMIT_NOFILE, which the kernel enforces, and
# how large a submission queue may be is what the kernel accepts when
# the ring asks from the top down. Nothing of ours is left to pin.
WM_FD = Webmachine::SpecFd unless defined?(WM_FD)

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

