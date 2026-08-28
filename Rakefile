MRUBY_DIR = File.expand_path('mruby', __dir__)
CONFIG = File.expand_path(ENV['MRUBY_CONFIG'] || 'build_config_host.rb', __dir__)

file MRUBY_DIR do
  sh "git clone --depth 1 https://github.com/mruby/mruby.git #{MRUBY_DIR}"
end

desc 'build'
task compile: MRUBY_DIR do
  sh "git -C #{MRUBY_DIR} --no-pager log -1 --format='mruby %h %ad' --date=short"
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake"
end

desc 'build and run every test'
task test: MRUBY_DIR do
  warn_on_gem_drift
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake all test"
  Rake::Task[:ship_smoke].invoke
  Rake::Task[:portable_smoke].invoke
end

def wm_smoke(build_name, label)
  require 'socket'
  bin = File.expand_path("mruby/build/#{build_name}/bin/webmachine-server", __dir__)
  raise "no #{label} binary at #{bin} - run rake compile first" unless File.executable?(bin)

  sock = "/tmp/wm-#{build_name}-smoke-#{$$}.sock"
  log = "/tmp/wm-#{build_name}-smoke-#{$$}.log"
  File.unlink(sock) if File.exist?(sock)
  pid = spawn(bin, '--unix', sock, out: File::NULL, err: log)
  begin
    200.times do
      break if File.socket?(sock)
      sleep 0.05
    end
    unless File.socket?(sock)
      text = begin File.read(log) rescue '' end
      if text.include?('io_uring is not usable here')
        warn "#{build_name} smoke: skipped - this machine cannot run io_uring " \
             "(the #{label} binary needs it, no fallback); use " \
             "build_config_portable.rb or build_config_portable_debug.rb here instead"
        return
      end
      raise "the #{label} binary never came up:\n#{text}"
    end
    answer = UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: smoke\r\nConnection: close\r\n\r\n")
      s.read
    end
    unless answer.start_with?('HTTP/1.1 200')
      raise "the #{label} binary answered:\n#{answer}"
    end
    puts "#{build_name} smoke: the #{label} binary starts and answers 200"
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    File.unlink(log) rescue nil
  end
end

desc 'the SHIP binary starts and answers - what the suite (debug) never checks'
task :ship_smoke do
  wm_smoke('host', 'shipped')
end

desc 'the PORTABLE binary (no liburing, select(2)) starts and answers'
task :portable_smoke do
  wm_smoke('portable', 'portable')
end

# WHERE A GEM REVISION ACTUALLY COMES FROM. Not the checkout under
# mruby/build/repos/<build>/<name> - that is downstream and gets reset
# on the next build. The authority is <config>.lock, which records a
# `commit:` per gem per build and makes the build check exactly that
# out. `branch: main` in a build config only decides what gets locked
# the FIRST time; afterwards the lock rules and nothing ever moves.
#
# So the locks drift apart per config, silently. Found the hard way
# (2026-08-28): build_config_debug.rb.lock had slipstreamIO pinned six
# days behind every other config, which means the suite - the thing
# that certifies the tree - was testing an older engine than the
# binary anyone shipped, and nothing said so. The locks are untracked
# per-machine state, so git could not have shown it either.
# Only the locks whose build config still exists. A lock left behind
# by a deleted config keeps naming revisions nobody builds any more,
# and counting it as drift buries the one gem that really did move
# under three that only ever moved on paper.
def lock_files
  Rake::FileList['build_config*.rb.lock'].select do |file|
    File.exist?(file.sub(/\.lock\z/, ''))
  end
end

# The ones deliberately left out above, so they are named rather than
# silently dropped.
def orphaned_locks
  Rake::FileList['build_config*.rb.lock'].reject do |file|
    File.exist?(file.sub(/\.lock\z/, ''))
  end
end

# url => { config => commit }, read off the locks. No network: the
# drift that bites is between OUR OWN configs, and that is answerable
# from the files alone.
def gem_locks
  require 'yaml'
  found = Hash.new { |h, k| h[k] = {} }
  lock_files.each do |file|
    doc = begin
      YAML.load_file(file)
    rescue StandardError => e
      warn "#{file}: cannot be read (#{e.class}) - skipped"
      next
    end
    next unless doc.is_a?(Hash) && doc['builds'].is_a?(Hash)

    config = File.basename(file, '.rb.lock')
    doc['builds'].each do |build, gems|
      next unless gems.is_a?(Hash)

      gems.each_value do |g|
        next unless g.is_a?(Hash) && g['url'] && g['commit']

        found[g['url']]["#{config}/#{build}"] =
          { commit: g['commit'], branch: g['branch'] }
      end
    end
  end
  found
end

def gem_short_name(url)
  File.basename(url, '.git')
end

# Offline, and silent unless there is something to say. Wired into
# `rake test` because a suite that certifies the tree while testing a
# revision no other build uses is worse than no suite: it passes, and
# the passing is what makes it invisible.
def warn_on_gem_drift
  drifted = gem_locks.reject do |_url, per_config|
    per_config.values.map { |v| v[:commit] }.uniq.size == 1
  end
  return if drifted.empty?

  warn ''
  warn "WARNING: #{drifted.size} gem(s) are locked to different revisions per config:"
  drifted.each_key { |url| warn "  #{gem_short_name(url)}" }
  warn 'This suite may not be testing what the other builds compile.'
  warn 'rake gems_status shows the revisions, rake gems_refresh levels them.'
  warn ''
end

desc 'which revision of each github gem every config has LOCKED'
task :gems_status do
  locked = gem_locks
  if locked.empty?
    puts 'no lock files here - run rake compile first'
    next
  end
  drifted = []
  locked.sort_by { |url, _| gem_short_name(url) }.each do |url, per_config|
    revs = per_config.values.map { |v| v[:commit] }.uniq
    drifted << gem_short_name(url) if revs.size > 1
    puts "#{revs.size > 1 ? 'DRIFT' : '  ok '} #{gem_short_name(url)}"
    per_config.sort.each do |config, v|
      puts "        #{v[:commit][0, 9]}  #{config} (#{v[:branch]})"
    end
  end
  orphaned_locks.each do |file|
    puts "(ignored: #{file} - its build config is gone)"
  end
  return if drifted.empty?

  puts
  puts "#{drifted.size} gem(s) locked to different revisions per config: #{drifted.join(', ')}"
  puts 'rake gems_refresh moves every lock to its branch head.'
end

# Optional argument: refresh one gem by name (rake gems_refresh[slipstreamIO]).
# Without it, every gem in every lock. One ls-remote per gem+branch,
# then the `commit:` line is rewritten IN PLACE - a targeted edit, so
# nothing else in a file mruby wrote gets reformatted underneath it.
desc 'point every lock at its branch head (optional: one gem by name)'
task :gems_refresh, [:gem] do |_t, args|
  only = args[:gem]
  heads = {}
  changed = 0
  lock_files.each do |file|
    text = File.read(file)
    original = text.dup
    gem_locks_in(file).each do |build, url, branch, commit|
      next if only && gem_short_name(url) != only

      key = [url, branch]
      unless heads.key?(key)
        line = `git ls-remote #{url} refs/heads/#{branch} 2>/dev/null`.lines.first.to_s
        heads[key] = line.split(/\s+/).first
      end
      head = heads[key]
      unless head
        warn "SKIP #{gem_short_name(url)} - cannot reach #{url} (#{branch})"
        next
      end
      next if head == commit

      text = text.sub("commit: #{commit}", "commit: #{head}")
      puts "MOVED #{File.basename(file, '.rb.lock')}/#{build}/" \
           "#{gem_short_name(url)} #{commit[0, 9]} -> #{head[0, 9]} (#{branch})"
      changed += 1
    end
    File.write(file, text) unless text == original
  end
  puts
  if changed.zero?
    puts 'every lock was already at its branch head.'
  else
    puts "#{changed} lock entr(ies) moved - the next build checks the new revision"
    puts 'out and recompiles. Rebuild before trusting any number: rake test'
  end
end

# [build, url, branch, commit] per gem in one lock, in file order.
def gem_locks_in(file)
  require 'yaml'
  doc = begin
    YAML.load_file(file)
  rescue StandardError
    return []
  end
  return [] unless doc.is_a?(Hash) && doc['builds'].is_a?(Hash)

  out = []
  doc['builds'].each do |build, gems|
    next unless gems.is_a?(Hash)

    gems.each_value do |g|
      next unless g.is_a?(Hash) && g['url'] && g['branch'] && g['commit']

      out << [build, g['url'], g['branch'], g['commit']]
    end
  end
  out
end

desc 'remove build output (keeps the mruby checkout)'
task :clean do
  sh "cd #{MRUBY_DIR} && MRUBY_CONFIG=#{CONFIG} rake clean" if File.directory?(MRUBY_DIR)
end

task default: :compile
