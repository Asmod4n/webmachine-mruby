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

# io_uring_queue_init_params takes the submission entry count first, and
# the queues it makes are locked memory charged to this process. Measured
# on a box with 8 MiB of it: two rings of 32768 entries come up and the
# third answers ENOMEM, because one such ring is 32768 * 64 for its
# submission queue plus 65536 * 16 for its completion queue, which is
# 3 MiB. Three quarters of the limit are the rings' to share; the kernel's
# own ceiling of 32768, written in its C code and unrelated to that limit,
# bounds the answer.
assert('fd: submission entries are three quarters of RLIMIT_MEMLOCK shared by the rings') do
  megs8 = 8 * 1024 * 1024
  # One ring: the share holds 65536 entries, over the ceiling.
  assert_equal 32_768, WM_FD.sq_entries(megs8, 1)
  # Two rings: 32768 each, which is what the box above brings up.
  assert_equal 32_768, WM_FD.sq_entries(megs8, 2)
  # Four rings - what --threads=3 opens - get 16384 each, and the four of
  # them come to the 6 MiB that three quarters of 8 MiB allows.
  assert_equal 16_384, WM_FD.sq_entries(megs8, 4)
  assert_equal 6 * 1024 * 1024, 4 * (16_384 * 64 + 32_768 * 16)
  # An operator who lifts the limit to 500 GiB still gets the ceiling.
  assert_equal 32_768, WM_FD.sq_entries(500 * 1024 * 1024 * 1024, 1)
  # A queue is a power of two, so the answer is the largest one that fits.
  assert_equal 512, WM_FD.sq_entries(64 * 1024, 1)
  assert_equal 512, WM_FD.sq_entries(100 * 1024, 1)
  # A limit too small for one entry answers one, and the setup then says
  # what the kernel said.
  assert_equal 1, WM_FD.sq_entries(64, 1)
  # The count defaults to one ring.
  assert_equal WM_FD.sq_entries(megs8, 1), WM_FD.sq_entries(megs8)
end
