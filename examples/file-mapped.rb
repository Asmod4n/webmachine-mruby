# response.file over the MAPPED path: statx, mmap, and chunks of the
# mapping lent to sends. Pair it with file-window.rb, which serves the
# same bytes through the read path, and the difference between the two
# log lines is what the second copy costs.
#
#   THREADS=3 CONNS=16 APP=examples/file-mapped.rb bench/floor.sh
#   THREADS=3 CONNS=16 APP=examples/file-window.rb bench/floor.sh
#
# Start LOW on CONNS: every request moves 4 MiB, so this arm goes
# bandwidth-bound long before hello.rb does, and floor.sh refuses a
# client-bound run rather than recording it. Raise CONNS until the
# server owns its core.
BENCH_ROOT = '/tmp/wm-bench-docroot'.freeze
BENCH_FILE = 'big.bin'.freeze
BENCH_SIZE = 4 * 1024 * 1024

def bench_docroot
  Dir.mkdir(BENCH_ROOT) unless Dir.exist?(BENCH_ROOT)
  path = File.join(BENCH_ROOT, BENCH_FILE)
  File.open(path, 'wb') { |f| f.write('B' * BENCH_SIZE) }
  BENCH_ROOT
end

class BigFile < Webmachine::Resource
  def to_html
    response.file = BENCH_FILE
    ''
  end
end

def main
  root = bench_docroot
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.conf.docroot = root
    # 1 MiB is the default; naming it keeps the two arms differing in
    # exactly one line.
    app.conf.file_map_threshold = 1024 * 1024
    app.add_route [:*], BigFile
  end
end
