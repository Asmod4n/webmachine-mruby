# RFC 9110 5.6.2 Tokens
# A token is a name without quotes: a header field name, a method, a
# parameter name. It holds letters, digits, and these 15 marks:
#     ! # $ % & ' * + - . ^ _ ` | ~
# Nothing else. No space, no tab, no colon, no bracket, no quote.
#
# The list below is read off the RFC and not built from the table under
# test, so a wrong table has something to disagree with.
TCHAR = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a +
        %w[! # $ % & ' * + - . ^ _ ` | ~]

assert('is_tchar answers RFC 9110 5.6.2 for every one of the 256 bytes') do
  256.times do |byte|
    assert_equal TCHAR.include?(byte.chr), Webmachine::SpecHttp.tchar?(byte),
                 "byte #{byte}"
  end
end

SECTION = 0
RULE    = 1
TITLE   = 2
ALLOWED = 3
STATUS  = 4
OFFSET  = 5
FOUND   = 6
EXCERPT = 7

UNKNOWN_PROBLEM       = 0
TCHAR_PROBLEM         = 1
QUOTED_STRING_PROBLEM = 2
QDTEXT_PROBLEM        = 3

# A log reader has to see which rule refused and which byte did it.
# Without the byte, a bad quote and a control character read the same.
assert('ParseError names the section, the rule and the byte') do
  e = Webmachine::SpecHttp.parse_error(QDTEXT_PROBLEM, "\"ab\x01c\"", 3)
  assert_equal 'RFC 9110 5.6.4', e[SECTION]
  assert_equal 'qdtext', e[RULE]
  assert_equal 'HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text', e[ALLOWED]
  assert_equal 400, e[STATUS]
  assert_equal 3, e[OFFSET]
  assert_equal 1, e[FOUND]
end

# The read buffer goes back to the kernel after the feed, so the record
# keeps its own copy of the bytes it refused.
assert('ParseError copies the excerpt and leaves it raw') do
  e = Webmachine::SpecHttp.parse_error(QDTEXT_PROBLEM, "\"ab\x01c\"", 3)
  assert_equal "\"ab\x01c\"", e[EXCERPT]
end

# One long field value may not grow the record.
assert('ParseError holds at most 32 bytes of the text') do
  e = Webmachine::SpecHttp.parse_error(QDTEXT_PROBLEM, 'a' * 200, 100)
  assert_equal 32, e[EXCERPT].size
end

# Under offset 16 there is nothing in front of the byte to show.
assert('ParseError starts the excerpt at the text when the offset is small') do
  e = Webmachine::SpecHttp.parse_error(QDTEXT_PROBLEM, 'abcdef', 2)
  assert_equal 'abcdef', e[EXCERPT]
end

# A truncated read gives exactly this, and the record may not read past
# the text it was handed.
assert('ParseError reports byte zero when the offset is past the end') do
  e = Webmachine::SpecHttp.parse_error(QDTEXT_PROBLEM, 'abc', 9)
  assert_equal 0, e[FOUND]
  assert_equal 9, e[OFFSET]
end

# Problem zero is what ErrRec carries for a raise out of the app, which
# has no rule of ours behind it.
assert('problem zero names nothing and has no status') do
  e = Webmachine::SpecHttp.parse_error(UNKNOWN_PROBLEM, 'abc', 0)
  assert_equal '', e[SECTION]
  assert_equal '', e[RULE]
  assert_equal 0, e[STATUS]
end

# RFC 9110 5.6.2 and 5.6.4 refuse different things, and a reader has to
# see which one refused.
assert('each problem carries its own section and rule') do
  t = Webmachine::SpecHttp.parse_error(TCHAR_PROBLEM, 'a:b', 1)
  q = Webmachine::SpecHttp.parse_error(QUOTED_STRING_PROBLEM, 'ab', 0)
  assert_equal 'RFC 9110 5.6.2', t[SECTION]
  assert_equal 'tchar', t[RULE]
  assert_equal 'The field name is not valid', t[TITLE]
  assert_equal 'RFC 9110 5.6.4', q[SECTION]
  assert_equal 'quoted-string', q[RULE]
  assert_equal 'The field value is not valid', q[TITLE]
end
