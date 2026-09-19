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
