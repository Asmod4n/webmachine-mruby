
# response.file's step machine, without a server. Every size here used to
# need a socket; the three past 2 GiB used to need the disk as well.
SIZES = [
  0, 1, 4096,
  FileVectors::WINDOW - 1, FileVectors::WINDOW, FileVectors::WINDOW + 1,
  4 << 20, 16 << 20,
  FileVectors::SEND_CHUNK - 1, FileVectors::SEND_CHUNK, FileVectors::SEND_CHUNK + 1,
  3 * (1 << 30), 5 * (1 << 30)
].freeze

assert('file_step: mruby carries the sizes this test needs') do
  assert_equal 5368709120, 5 * (1 << 30)
end

assert('file_step: a mapped transfer sends every byte once, in order') do
  SIZES.each do |n|
    rounds, bytes, maxchunk, contiguous, logs, releases, rwb, heads =
      FileVectors.walk(n, 1, FileVectors::WINDOW)
    assert_equal n, bytes, "total #{n}: bytes"
    assert_true contiguous, "total #{n}: offsets are contiguous"
    assert_true maxchunk <= FileVectors::SEND_CHUNK, "total #{n}: chunk within MAX_RW_COUNT"
    assert_equal 1, logs, "total #{n}: one access line"
    assert_equal 1, heads, "total #{n}: the head rides one round"
    assert_true rounds > 0
  end
  true
end

# The bug of 2026-08-26: the release ran in the very call that was about to
# lend, `map` was null when the plan was built, and the send walked the
# window buffer for the file's whole length - 109_632 bytes of the wrong
# memory on the wire. It is a property, so it gets a property test.
assert('file_step: a mapping is never released in a round that lends it') do
  SIZES.each do |n|
    _, _, _, _, _, releases, release_with_body, _ =
      FileVectors.walk(n, 1, FileVectors::WINDOW)
    assert_false release_with_body, "total #{n}: released while lending"
    assert_equal 1, releases, "total #{n}: released exactly once"
  end
  true
end

assert('file_step: the window path sends every byte once, one line, one head') do
  SIZES.each do |n|
    _, bytes, maxchunk, _, logs, releases, _, heads =
      FileVectors.walk(n, 0, FileVectors::WINDOW)
    assert_equal n, bytes, "total #{n}: bytes"
    assert_true maxchunk <= FileVectors::WINDOW, "total #{n}: never past the window"
    assert_equal 1, logs, "total #{n}: one access line, not one per window"
    assert_equal 1, heads, "total #{n}: the head rides one round"
    assert_equal 0, releases, "total #{n}: nothing mapped, nothing to release"
  end
  true
end

# A 3 GiB body offered to ONE sendmsg comes back at MAX_RW_COUNT and reads
# exactly like a dead peer. The chunk is what keeps that from happening.
assert('file_step: no lend can be refused by the kernel as too large') do
  n = 5 * (1 << 30)
  rounds, bytes, maxchunk, = FileVectors.walk(n, 1, FileVectors::WINDOW)
  assert_equal n, bytes
  assert_true maxchunk <= 2147479552, 'a lend must fit MAX_RW_COUNT'
  assert_true rounds >= n / FileVectors::SEND_CHUNK, 'a big file takes several rounds'
  true
end
