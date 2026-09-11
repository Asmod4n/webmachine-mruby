# The sniff table (src/sniff.cpp), row by row, and the rule that reads
# it. The table is the WHATWG MIME Sniffing Standard's; these cases are
# what the rule does with it.
S = Webmachine::SpecSniff unless defined?(S)

PNG = "\x89PNG\r\n\x1a\n".b + ("\x00" * 16)
JPEG = "\xff\xd8\xff\xe0".b + ("\x00" * 16)
GIF = 'GIF89a'.b + ("\x00" * 16)
PDF = '%PDF-1.7'.b + ("\x00" * 16)
ZIP = "PK\x03\x04".b + ("\x00" * 16)
MP4 = ("\x00\x00\x00\x18" + 'ftypisom').b + ("\x00" * 16)
WEBP = ('RIFF' + "\x00\x00\x00\x00" + 'WEBP').b + ("\x00" * 16)
TEXT = "the quick brown fox\n".b * 4

assert('sniff: a type the table knows must match its own octets') do
  assert_equal :agrees, S.check('image/png', PNG)
  assert_equal :agrees, S.check('image/jpeg', JPEG)
  assert_equal :agrees, S.check('image/gif', GIF)
  assert_equal :agrees, S.check('application/pdf', PDF)
  assert_equal :agrees, S.check('video/mp4', MP4)
  assert_equal :agrees, S.check('image/webp', WEBP)
  # The parameters are not part of the type.
  assert_equal :agrees, S.check('image/png; charset=binary', PNG)
  # Upper case is the same type.
  assert_equal :agrees, S.check('IMAGE/PNG', PNG)
end

assert('sniff: a type the table knows, with the wrong octets, contradicts') do
  assert_equal :contradicts, S.check('image/png', JPEG)
  assert_equal :contradicts, S.check('image/jpeg', PNG)
  # Both are images, and that is not a defence.
  assert_equal :contradicts, S.check('image/gif', PNG)
  assert_equal :contradicts, S.check('video/mp4', PDF)
end

assert('sniff: an mp4 declared as a text file is refused') do
  # The case this check exists for: the table cannot confirm
  # text/plain, so it asks what the octets are instead, and they name a
  # concrete format of another family.
  assert_equal :contradicts, S.check('text/plain', MP4)
  assert_equal :contradicts, S.check('application/json', PNG)
  assert_equal :contradicts, S.check('text/csv', PDF)
end

assert('sniff: a container never contradicts') do
  # Every docx, epub, jar and odt is a zip. A zip pattern under a
  # declaration the table cannot confirm says nothing.
  assert_equal :unknown, S.check('application/vnd.openxmlformats-officedocument.wordprocessingml.document', ZIP)
  assert_equal :unknown, S.check('application/epub+zip', ZIP)
  assert_equal :agrees, S.check('application/zip', ZIP)
end

assert('sniff: octets nothing recognises never refuse') do
  assert_equal :unknown, S.check('text/plain', TEXT)
  assert_equal :unknown, S.check('application/json', '{"a":1}'.b)
  assert_equal :unknown, S.check('application/octet-stream', TEXT)
end

assert('sniff: a short buffer waits rather than refusing') do
  # Two octets of a PNG are not yet a contradiction: the rest may still
  # arrive. A type the table knows only fails once enough has come.
  assert_equal :unknown, S.check('image/png', "\x89P".b)
  assert_equal :unknown, S.check('image/png', ''.b)
end

assert('sniff: known? is what the fold asks') do
  assert_true S.known?('image/png')
  assert_true S.known?('video/mp4')
  assert_true S.known?('application/pdf')
  assert_false S.known?('text/plain')
  assert_false S.known?('application/json')
end
