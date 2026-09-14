# The descriptor budget (src/ring_setup.hpp) and the count of open request
# body files (src/docroot.cpp), driven through Webmachine::SpecFd.
WM_FD = Webmachine::SpecFd unless defined?(WM_FD)

assert('fd: max_conns is the limit minus the reserve, the body files and the listeners') do
  # The registered file table holds kFixedTableKernelMax slots, listeners
  # included, so a large limit answers that ceiling minus the listeners.
  assert_equal 496, WM_FD.max_conns(20_000)
  # 1168 is taken whole; 1169 leaves one connection.
  assert_equal 0, WM_FD.max_conns(1168)
  assert_equal 1, WM_FD.max_conns(1169)
  assert_equal 496, WM_FD.max_conns(1 << 21)
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

# io_uring_queue_init_params takes the submission entry count first, and
# the queues it makes are locked memory charged to the user this process
# runs as. One entry costs its submission slot and its two completion
# slots. Three quarters of RLIMIT_MEMLOCK are the rings' to share, and
# kSqEntriesMax bounds the answer.
assert('fd: submission entries are three quarters of RLIMIT_MEMLOCK shared by the rings') do
  megs8 = 8 * 1024 * 1024
  # Room for more than the ceiling gives the ceiling, whatever the ring
  # count is.
  assert_equal 512, WM_FD.sq_entries(megs8, 1)
  assert_equal 512, WM_FD.sq_entries(megs8, 2)
  assert_equal 512, WM_FD.sq_entries(megs8, 4)
  # An operator who lifts the limit to 500 GiB still gets the ceiling.
  assert_equal 512, WM_FD.sq_entries(500 * 1024 * 1024 * 1024, 1)
  # Four rings at the ceiling come to 192 KiB of locked memory.
  assert_equal 192 * 1024, 4 * (512 * 64 + 1024 * 16)
  # A queue is a power of two, so a smaller share answers the largest one
  # that fits.
  assert_equal 256, WM_FD.sq_entries(32 * 1024, 1)
  assert_equal 512, WM_FD.sq_entries(100 * 1024, 1)
  # A limit too small for one entry answers one, and the setup then says
  # what the kernel said.
  assert_equal 1, WM_FD.sq_entries(64, 1)
  # The count defaults to one ring.
  assert_equal WM_FD.sq_entries(megs8, 1), WM_FD.sq_entries(megs8)
end
