# The types this suite proves, written down where they are true.
#
# mruby-lsp reads a test suite for the types it can prove: an assertion
# that names a class is a fact about the method, and this suite checks it
# against the real VM on every run. An attr_reader has no C function to
# read and no value to infer, so an assertion is the only thing that says
# what it gives back.
assert('app.conf is a Config') do
  assert_kind_of Webmachine::Config, Webmachine::Application.new.conf
end

assert('conf: a member gives back the class it was given') do
  c = Webmachine::Config.new
  c.port = 8080
  c.docroot = 'public'
  c.unix_path = '/tmp/wm.sock'
  c.assets = 'site.zip'
  c.file_map_threshold = 4096

  assert_kind_of Integer, c.port
  assert_kind_of String, c.docroot
  assert_kind_of String, c.unix_path
  assert_kind_of String, c.assets
  assert_kind_of Integer, c.file_map_threshold
end

assert('conf: a member nobody set is nil') do
  c = Webmachine::Config.new
  assert_nil c.port
  assert_nil c.docroot
  assert_nil c.unix_path
  assert_nil c.assets
  assert_nil c.file_map_threshold
end
