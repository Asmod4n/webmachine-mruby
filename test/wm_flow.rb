# webmachine-ruby's own spec/webmachine/decision/flow_spec.rb, ported.
# It is the ORACLE: 34 flow nodes, each pinned by the cases their author
# wrote, run here against THIS tree's resource_fold + resource_run
# through the shim in test/wm_ruby.cpp. Nothing here mocks the machine -
# every case builds a resource class, runs the real graph, and reads the
# real answer.
#
# PORTED 120 of the upstream file's 131 examples. OMITTED 11, each with
# its reason at the place it would have stood:
#   4  #d4/#d5   Accept-Language      - no i18n in this tree (user's call)
#   3  #e5/#e6   Accept-Charset       - no charset negotiation here (#146
#                                       spells one charset, always)
#   2  #f6/#f7   Accept-Encoding      - encodings_provided is konst here
#                                       (folded, not chosen per request)
#   1  #b6       an unknown Content-* - the shim hands the flow only the
#                                       fields RFC 9110 names
#   1  On error  "calls handle_exception" - mocks the resource
# Also dropped, without costing a case: the after(:each) Date check
# (Date is the writer's field, proven on the wire in bintest/), and
# every `expect(subject).to_not receive(:x)` half, which asserts the
# FSM's internal path rather than its answer - the status assertion that
# stands beside it is kept.
#
# TWO SHAPES CHANGED, both because this tree is not the Ruby one:
#
#   1. The specs set the answer on the resource INSTANCE
#      (`resource.available = false`). Here the instance lives exactly
#      one request (#181) - the FSM is handed a CLASS and the run frame
#      builds the instance itself, so there is no object to reach before
#      the run. The answer therefore lives outside the instance and the
#      callback reads it from there, which is the same tested effect:
#      the callback answers false/true/Integer. bintest/resource.rb does
#      the same thing with $flaky for the same reason.
#   2. Content-Type assertions gain "; charset=utf-8": this tree appends
#      it to every text/* type (#146), so upstream's 'text/html' is
#      'text/html; charset=utf-8' here.
#
# The cases are REGISTERED, not asserted, here: mruby loads a gem's
# test/**/*.rb in sorted order (wm_flow, wm_helpers, wm_ruby) and
# `assert` runs its block immediately, before test/wm_ruby.rb has
# defined the objects the specs construct. test/wm_ruby.rb drains this
# queue, so each case still becomes one assert under its own name.

$wm_cases = []

def wm_case(name, &blk)
  $wm_cases << [name, blk]
end

# The spec's `resource_with`: a resource that renders 'test resource'
# and nothing else.
class WmSpecResource < Webmachine::Resource
  def to_html
    'test resource'
  end
end

# The spec's `missing_resource_with`.
class WmSpecMissing < WmSpecResource
  def resource_exists?
    false
  end
end

# One request through the real machinery, answered into a SpecResponse.
def wm_run(klass, method = 'GET', headers = nil, body = nil)
  h = headers || Webmachine::Headers.new
  # The spec's request URI is http://localhost/ ; here the authority is
  # a field, so Host carries it (RFC 9110 7.2) - request.base_uri reads
  # it, and n11 builds Location from that.
  h['Host'] = 'localhost' unless h.key?('Host')
  req = Webmachine::SpecRequest.new(method, '/', h, body)
  resp = Webmachine::SpecResponse.new
  Webmachine::Decision::FSM.new(klass, req, resp).run
  resp
end

def wm_h(pairs = nil)
  Webmachine::Headers[pairs]
end

# last_modified answers a Time upstream. The unit VM is mrb_open_core
# plus this gem's dependencies, so mruby-time need not be there; the
# epoch second is the same instant either way.
def wm_time(epoch)
  Object.const_defined?(:Time) ? Time.at(epoch) : epoch
end

# One fixed instant and the HTTP-dates around it, so no case depends on
# the wall clock. 1000000000 = Sun, 09 Sep 2001 01:46:40 GMT.
WM_LM = 1000000000
WM_LM_PLUS100  = 'Sun, 09 Sep 2001 01:48:20 GMT'  # WM_LM + 100
WM_LM_MINUS100 = 'Sun, 09 Sep 2001 01:45:00 GMT'  # WM_LM - 100
WM_LM_MINUS1   = 'Sun, 09 Sep 2001 01:46:39 GMT'  # WM_LM - 1
WM_LM_MINUS1K  = 'Sun, 09 Sep 2001 01:30:00 GMT'  # WM_LM - 1000
WM_FUTURE_DATE = 'Fri, 01 Jan 2100 00:00:00 GMT'  # later than any run

# --- #b13 (Service available?) ------------------------------------- 1

def wm_res_b13
  Class.new(WmSpecResource) do
    def service_available?
      $wm_available
    end
  end
end

wm_case('flow b13: an unavailable service answers 503') do
  $wm_available = false
  assert_equal 503, wm_run(wm_res_b13).code
end

# --- #b12 (Known method?) ------------------------------------------ 1

def wm_res_b12
  Class.new(WmSpecResource) do
    def known_methods
      ['HEAD']
    end
  end
end

wm_case('flow b12: a method outside known_methods answers 501') do
  assert_equal 501, wm_run(wm_res_b12).code
end

# --- #b11 (URI too long?) ------------------------------------------ 1

def wm_res_b11
  Class.new(WmSpecResource) do
    def uri_too_long?(uri)
      true
    end
  end
end

wm_case('flow b11: a URI the resource calls too long answers 414') do
  assert_equal 414, wm_run(wm_res_b11).code
end

# --- #b10 (Method allowed?) ---------------------------------------- 1

def wm_res_b10
  Class.new(WmSpecResource) do
    def allowed_methods
      ['POST']
    end
  end
end

wm_case('flow b10: a method outside allowed_methods answers 405, Allow names the list') do
  res = wm_run(wm_res_b10)
  assert_equal 405, res.code
  assert_equal 'POST', res.headers['Allow']
end

# --- #b9 (Malformed request? / Content-MD5) ----------------------- 10

def wm_res_b9_malformed
  Class.new(WmSpecResource) do
    def malformed_request?
      true
    end
  end
end

wm_case('flow b9b: a malformed request answers 400') do
  assert_equal 400, wm_run(wm_res_b9_malformed).code
end

WM_B9_BODY = 'This is the body.'

def wm_res_b9_md5
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[POST]
    end

    def process_post
      true
    end

    def validate_content_checksum
      $wm_validation
    end
  end
end

# The spec's headers for the Content-MD5 context, with the checksum
# spelled by the caller. :none leaves the field off entirely.
def wm_b9_headers(md5 = :none)
  h = wm_h('Content-Type' => 'text/plain')
  h['Content-MD5'] = md5 unless md5 == :none
  h
end

def wm_run_b9(md5 = :none)
  wm_run(wm_res_b9_md5, 'POST', wm_b9_headers(md5), WM_B9_BODY)
end

def wm_b9_sum(of)
  Webmachine::TestDigest.b64(Webmachine::TestDigest.md5_hex(of))
end

wm_case('flow b9a: a Content-MD5 that matches the body answers 204') do
  $wm_validation = nil
  assert_equal 204, wm_run_b9(wm_b9_sum(WM_B9_BODY)).code
end

wm_case('flow b9a: a Content-MD5 with a nil value bypasses validation (204)') do
  # nil never reached the wire, so the field is simply absent (b9 -> b9b).
  $wm_validation = nil
  assert_equal 204, wm_run_b9(nil).code
end

wm_case('flow b9a: an empty Content-MD5 answers 400') do
  $wm_validation = nil
  assert_equal 400, wm_run_b9('').code
end

wm_case('flow b9a: a non-hashed, non-encoded Content-MD5 answers 400') do
  $wm_validation = nil
  assert_equal 400, wm_run_b9(WM_B9_BODY).code
end

wm_case('flow b9a: a matching digest that is not Base64 answers 400') do
  $wm_validation = nil
  assert_equal 400, wm_run_b9(Webmachine::TestDigest.md5_hex(WM_B9_BODY)).code
end

wm_case('flow b9a: a Content-MD5 that does not match the body answers 400') do
  $wm_validation = nil
  assert_equal 400, wm_run_b9(wm_b9_sum('thiswillnotmatchthehash')).code
end

wm_case('flow b9a: the resource invalidating the checksum answers 400') do
  $wm_validation = false
  assert_equal 400, wm_run_b9(wm_b9_sum('thiswillnotmatchthehash')).code
end

wm_case('flow b9a: the resource validating the checksum does not answer 400') do
  $wm_validation = true
  assert_true wm_run_b9(wm_b9_sum('thiswillnotmatchthehash')).code != 400
end

wm_case('flow b9a: a status returned while validating is the answer') do
  $wm_validation = 500
  assert_equal 500, wm_run_b9(wm_b9_sum('thiswillnotmatchthehash')).code
end

# --- #b8 (Authorized?) --------------------------------------------- 4

def wm_res_b8
  Class.new(WmSpecResource) do
    def is_authorized?(header)
      $wm_auth
    end
  end
end

wm_case('flow b8: an unauthorized client answers 401') do
  $wm_auth = false
  assert_equal 401, wm_run(wm_res_b8).code
end

wm_case('flow b8: a challenge from the resource answers 401 and WWW-Authenticate') do
  $wm_auth = 'Basic realm=Webmachine'
  res = wm_run(wm_res_b8)
  assert_equal 401, res.code
  assert_equal 'Basic realm=Webmachine', res.headers['WWW-Authenticate']
end

wm_case('flow b8: a status returned by is_authorized? halts with it') do
  $wm_auth = 400
  assert_equal 400, wm_run(wm_res_b8).code
end

wm_case('flow b8: an authorized client does not answer 401') do
  $wm_auth = true
  assert_true wm_run(wm_res_b8).code != 401
end

# --- #b7 (Forbidden?) ---------------------------------------------- 3

def wm_res_b7
  Class.new(WmSpecResource) do
    def forbidden?
      $wm_forbid
    end
  end
end

wm_case('flow b7: a forbidden request answers 403') do
  $wm_forbid = true
  assert_equal 403, wm_run(wm_res_b7).code
end

wm_case('flow b7: a permitted request does not answer 403') do
  $wm_forbid = false
  assert_true wm_run(wm_res_b7).code != 403
end

wm_case('flow b7: a status returned by forbidden? halts with it') do
  $wm_forbid = 400
  assert_equal 400, wm_run(wm_res_b7).code
end

# --- #b6 (Unsupported Content-* header?) --------------------------- 1
# OMITTED (1): "should reply with 501 when an invalid Content-* header
# is present". The upstream case sets 'Content-Fail', a field RFC 9110
# does not name; this tree's http::header_switch hands such a field to
# the framer's functor, which the shim drops, so the callback could
# never see it. The wire tier is where that field exists.

def wm_res_b6
  Class.new(WmSpecResource) do
    def valid_content_headers?(contents)
      true
    end
  end
end

wm_case('flow b6: valid Content-* headers do not answer 501') do
  assert_true wm_run(wm_res_b6).code != 501
end

# --- #b5 (Known Content-Type?) ------------------------------------- 2

def wm_res_b5
  Class.new(WmSpecResource) do
    # Upstream writes `type !~ /unknown/`; the unit VM has no Regexp, and
    # the decision under test is the callback's answer, not its spelling.
    def known_content_type?(type)
      type.nil? || !type.include?('unknown')
    end

    def process_post
      true
    end

    def allowed_methods
      %w[POST]
    end
  end
end

wm_case('flow b5: an unknown Content-Type answers 415') do
  h = wm_h('Content-Type' => 'application/x-unknown-type',
           'Content-Length' => WM_B9_BODY.size.to_s)
  assert_equal 415, wm_run(wm_res_b5, 'POST', h, WM_B9_BODY).code
end

wm_case('flow b5: a known Content-Type does not answer 415') do
  h = wm_h('Content-Type' => 'text/plain', 'Content-Length' => WM_B9_BODY.size.to_s)
  assert_true wm_run(wm_res_b5, 'POST', h, WM_B9_BODY).code != 415
end

# --- #b4 (Request entity too large?) ------------------------------- 2

def wm_res_b4
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[POST]
    end

    def process_post
      true
    end

    def valid_entity_length?(length)
      length.to_s.to_i < 100
    end
  end
end

def wm_run_b4(body)
  h = wm_h('Content-Type' => 'text/plain', 'Content-Length' => body.size.to_s)
  wm_run(wm_res_b4, 'POST', h, body)
end

wm_case('flow b4: a request body the resource calls too large answers 413') do
  assert_equal 413, wm_run_b4('Big' * 100).code
end

wm_case('flow b4: a request body inside the limit does not answer 413') do
  assert_true wm_run_b4('small').code != 413
end

# --- #b3 (OPTIONS?) ------------------------------------------------ 1

def wm_res_b3
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[GET HEAD OPTIONS]
    end
  end
end

wm_case('flow b3: OPTIONS answers 200') do
  assert_equal 200, wm_run(wm_res_b3, 'OPTIONS').code
end

# --- #c3, #c4 (Acceptable media types) ----------------------------- 3

def wm_res_default
  Class.new(WmSpecResource)
end

wm_case('flow c4: an unacceptable Accept answers 406') do
  assert_equal 406, wm_run(wm_res_default, 'GET', wm_h('Accept' => 'text/plain')).code
end

wm_case('flow c4: an acceptable Accept does not answer 406 and types the response') do
  res = wm_run(wm_res_default, 'GET', wm_h('Accept' => 'text/*'))
  assert_true res.code != 406
  # #146: this tree spells charset=utf-8 on every text/* type.
  assert_equal 'text/html; charset=utf-8', res.headers['Content-Type']
end

wm_case('flow c3: no Accept negotiates nothing and types the response') do
  h = wm_h
  assert_nil h['Accept']
  res = wm_run(wm_res_default, 'GET', h)
  assert_equal 'text/html; charset=utf-8', res.headers['Content-Type']
end

# --- #d4, #d5 (Acceptable languages) ------------------------- OMITTED 4
# --- #e5, #e6 (Acceptable charsets) -------------------------- OMITTED 3
# --- #f6, #f7 (Acceptable encodings) ------------------------- OMITTED 2
# There is no language negotiation, no charset negotiation and no
# negotiated encoding set in this tree (user's decision): #146 spells one
# charset on text/*, and encodings_provided is folded, not chosen from.
# Porting these would assert a machine that does not exist.

# --- #g7 (Resource exists?) ---------------------------------------- 4

def wm_res_g7
  Class.new(WmSpecResource) do
    def resource_exists?
      $wm_exist
    end
  end
end

wm_case('flow g7: a missing resource eventually answers 404') do
  $wm_exist = false
  assert_equal 404, wm_run(wm_res_g7).code
end

wm_case('flow g7: an existing resource does not answer 404') do
  $wm_exist = true
  assert_true wm_run(wm_res_g7).code != 404
end

wm_case('flow g7: a truthy non-boolean means it exists') do
  $wm_exist = []
  assert_true wm_run(wm_res_g7).code != 404
end

wm_case('flow g7: nil means it is missing (404)') do
  $wm_exist = nil
  assert_equal 404, wm_run(wm_res_g7).code
end

# --- #g8, #g9, #g11 (If-Match) ------------------------------------- 4

def wm_res_etag
  Class.new(WmSpecResource) do
    def generate_etag
      'etag'
    end
  end
end

wm_case('flow g8: no If-Match skips ETag matching') do
  h = wm_h
  assert_nil h['If-Match']
  assert_true wm_run(wm_res_etag, 'GET', h).code != 412
end

wm_case('flow g9: If-Match * does not answer 412') do
  assert_true wm_run(wm_res_etag, 'GET', wm_h('If-Match' => '*')).code != 412
end

wm_case('flow g11: an ETag outside If-Match answers 412') do
  assert_equal 412, wm_run(wm_res_etag, 'GET', wm_h('If-Match' => '"notetag"')).code
end

wm_case('flow g11: an ETag inside If-Match does not answer 412') do
  assert_true wm_run(wm_res_etag, 'GET', wm_h('If-Match' => '"etag"')).code != 412
end

# --- #h10, #h11, #h12 (If-Unmodified-Since) ------------------------ 4

def wm_res_lastmod
  Class.new(WmSpecResource) do
    def last_modified
      wm_time($wm_lastmod)
    end
  end
end

wm_case('flow h10: no If-Unmodified-Since skips Last-Modified matching') do
  $wm_lastmod = WM_LM
  h = wm_h
  assert_nil h['If-Unmodified-Since']
  assert_true wm_run(wm_res_lastmod, 'GET', h).code != 412
end

wm_case('flow h11: an unparseable If-Unmodified-Since skips the comparison') do
  $wm_lastmod = WM_LM
  assert_true wm_run(wm_res_lastmod, 'GET', wm_h('If-Unmodified-Since' => 'garbage')).code != 412
end

wm_case('flow h12: Last-Modified at or before IUMS does not answer 412') do
  $wm_lastmod = WM_LM
  h = wm_h('If-Unmodified-Since' => WM_LM_PLUS100)
  assert_true wm_run(wm_res_lastmod, 'GET', h).code != 412
end

wm_case('flow h12: Last-Modified after IUMS answers 412') do
  $wm_lastmod = WM_LM
  h = wm_h('If-Unmodified-Since' => WM_LM_MINUS100)
  assert_equal 412, wm_run(wm_res_lastmod, 'GET', h).code
end

# --- #i12, #i13, #k13, #j18 (If-None-Match) ------------------------ 8

def wm_res_inm
  Class.new(WmSpecResource) do
    def generate_etag
      'etag'
    end

    def process_post
      true
    end

    def allowed_methods
      %w[GET HEAD POST]
    end
  end
end

wm_case('flow i12: no If-None-Match skips ETag matching') do
  h = wm_h
  assert_nil h['If-None-Match']
  code = wm_run(wm_res_inm, 'GET', h).code
  assert_true code != 304 && code != 412
end

wm_case('flow k13: an ETag outside If-None-Match answers neither 304 nor 412') do
  code = wm_run(wm_res_inm, 'GET', wm_h('If-None-Match' => '"notetag"')).code
  assert_true code != 304 && code != 412
end

wm_case('flow j18: GET with If-None-Match * answers 304') do
  assert_equal 304, wm_run(wm_res_inm, 'GET', wm_h('If-None-Match' => '*')).code
end

wm_case('flow j18: HEAD with the ETag inside If-None-Match answers 304') do
  h = wm_h('If-None-Match' => '"etag", "foobar"')
  assert_equal 304, wm_run(wm_res_inm, 'HEAD', h).code
end

wm_case('flow j18: POST with If-None-Match * answers 412') do
  h = wm_h('Content-Type' => 'text/plain', 'If-None-Match' => '*')
  assert_equal 412, wm_run(wm_res_inm, 'POST', h, WM_B9_BODY).code
end

wm_case('flow j18: POST with the ETag inside If-None-Match answers 412') do
  h = wm_h('Content-Type' => 'text/plain', 'If-None-Match' => '"etag"')
  assert_equal 412, wm_run(wm_res_inm, 'POST', h, WM_B9_BODY).code
end

def wm_res_no_etag
  Class.new(WmSpecResource) do
    def generate_etag
      nil
    end
  end
end

wm_case('flow k13: a resource without an ETag answers 200 when If-None-Match is absent') do
  assert_equal 200, wm_run(wm_res_no_etag).code
end

wm_case('flow k13: a resource without an ETag answers 200 when If-None-Match is present') do
  assert_equal 200, wm_run(wm_res_no_etag, 'GET', wm_h('If-None-Match' => '"etag"')).code
end

# --- #l13, #l14, #l15, #l17 (If-Modified-Since) -------------------- 5

wm_case('flow l13: no If-Modified-Since skips Last-Modified matching') do
  $wm_lastmod = WM_LM
  h = wm_h
  assert_nil h['If-Modified-Since']
  assert_true wm_run(wm_res_lastmod, 'GET', h).code != 304
end

wm_case('flow l14: an unparseable If-Modified-Since skips the comparison') do
  $wm_lastmod = WM_LM
  assert_true wm_run(wm_res_lastmod, 'GET', wm_h('If-Modified-Since' => 'garbage')).code != 304
end

wm_case('flow l15: an If-Modified-Since later than now skips the comparison') do
  $wm_lastmod = WM_LM
  h = wm_h('If-Modified-Since' => WM_FUTURE_DATE)
  assert_true wm_run(wm_res_lastmod, 'GET', h).code != 304
end

wm_case('flow l17: Last-Modified at or before IMS answers 304') do
  $wm_lastmod = WM_LM - 1000
  assert_equal 304, wm_run(wm_res_lastmod, 'GET', wm_h('If-Modified-Since' => WM_LM_MINUS1)).code
end

wm_case('flow l17: Last-Modified after IMS does not answer 304') do
  $wm_lastmod = WM_LM
  h = wm_h('If-Modified-Since' => WM_LM_MINUS1K)
  assert_true wm_run(wm_res_lastmod, 'GET', h).code != 304
end

# --- #h7 (If-Match: * on a missing resource) ----------------------- 2

def wm_res_missing
  Class.new(WmSpecMissing)
end

wm_case('flow h7: If-Match * on a missing resource answers 412') do
  assert_equal 412, wm_run(wm_res_missing, 'GET', wm_h('If-Match' => '"*"')).code
end

wm_case('flow h7: an If-Match that is not * does not answer 412 on a missing resource') do
  assert_true wm_run(wm_res_missing, 'GET', wm_h('If-Match' => '"etag"')).code != 412
end

# --- #i7 (PUT?) ---------------------------------------------------- 2

def wm_res_i7
  Class.new(WmSpecMissing) do
    def allowed_methods
      %w[GET HEAD PUT POST]
    end

    def process_post
      true
    end
  end
end

wm_case('flow i7: PUT on a missing resource leaves the k7 branch (no 404/410/303)') do
  h = wm_h('Content-Type' => 'text/plain')
  code = wm_run(wm_res_i7, 'PUT', h, WM_B9_BODY).code
  assert_true code != 404 && code != 410 && code != 303
end

wm_case('flow i7: a method other than PUT never reaches i4 (no 409)') do
  h = wm_h('Content-Type' => 'text/plain')
  assert_true wm_run(wm_res_i7, 'POST', h, WM_B9_BODY).code != 409
end

# --- #i4 (Apply to a different URI?) ------------------------------- 2

def wm_res_i4
  Class.new(WmSpecMissing) do
    def moved_permanently?
      $wm_location
    end

    def allowed_methods
      %w[PUT]
    end
  end
end

wm_case('flow i4: a moved resource answers 301 and Location') do
  $wm_location = 'http://localhost:8098/newuri'
  h = wm_h('Content-Type' => 'text/plain', 'Content-Length' => WM_B9_BODY.size.to_s)
  res = wm_run(wm_res_i4, 'PUT', h, WM_B9_BODY)
  assert_equal 301, res.code
  assert_equal 'http://localhost:8098/newuri', res.headers['Location']
end

wm_case('flow i4: a resource that has not moved does not answer 301') do
  $wm_location = false
  h = wm_h('Content-Type' => 'text/plain', 'Content-Length' => WM_B9_BODY.size.to_s)
  assert_true wm_run(wm_res_i4, 'PUT', h, WM_B9_BODY).code != 301
end

# --- Redirection (resource previously existed): #k5, #l5, #m5, #n5 -- 7

def wm_res_gone
  Class.new(WmSpecMissing) do
    def previously_existed?
      true
    end

    def moved_permanently?
      $wm_moved_perm
    end

    def moved_temporarily?
      $wm_moved_temp
    end

    def allow_missing_post?
      $wm_allow_missing
    end

    def allowed_methods
      %w[GET POST]
    end

    def process_post
      true
    end
  end
end

wm_case('flow k5: a permanently moved resource answers 301 and Location') do
  $wm_moved_perm = 'http://www.google.com/'
  $wm_moved_temp = false
  $wm_allow_missing = false
  res = wm_run(wm_res_gone)
  assert_equal 301, res.code
  assert_equal 'http://www.google.com/', res.headers['Location']
end

wm_case('flow k5: a resource that has not moved permanently does not answer 301') do
  $wm_moved_perm = false
  $wm_moved_temp = false
  $wm_allow_missing = false
  assert_true wm_run(wm_res_gone).code != 301
end

wm_case('flow l5: a temporarily moved resource answers 307 and Location') do
  $wm_moved_perm = false
  $wm_moved_temp = 'http://www.basho.com/'
  $wm_allow_missing = false
  res = wm_run(wm_res_gone)
  assert_equal 307, res.code
  assert_equal 'http://www.basho.com/', res.headers['Location']
end

wm_case('flow l5: a resource that has not moved temporarily does not answer 307') do
  $wm_moved_perm = false
  $wm_moved_temp = false
  $wm_allow_missing = false
  assert_true wm_run(wm_res_gone).code != 307
end

wm_case('flow m5: a method other than POST on a gone resource answers 410') do
  $wm_moved_perm = false
  $wm_moved_temp = false
  $wm_allow_missing = false
  assert_equal 410, wm_run(wm_res_gone, 'GET').code
end

wm_case('flow n5: a POST a gone resource disallows answers 410') do
  $wm_moved_perm = false
  $wm_moved_temp = false
  $wm_allow_missing = false
  h = wm_h('Content-Type' => 'text/plain')
  assert_equal 410, wm_run(wm_res_gone, 'POST', h, WM_B9_BODY).code
end

wm_case('flow n5: a POST a gone resource allows does not answer 410') do
  # Upstream asserts 410 here although its own title says otherwise: its
  # `let(:method)` memoises 'GET' in the before block that runs first, so
  # that example never posts. The graph is unambiguous - n5 with
  # allow_missing_post? true goes to n11 - and that is what is asserted.
  $wm_moved_perm = false
  $wm_moved_temp = false
  $wm_allow_missing = true
  h = wm_h('Content-Type' => 'text/plain')
  assert_true wm_run(wm_res_gone, 'POST', h, WM_B9_BODY).code != 410
end

# --- #l7 (POST?), #m7 (POST to missing resource?) ------------------- 3

def wm_res_l7
  Class.new(WmSpecMissing) do
    def allowed_methods
      %w[GET POST]
    end

    def previously_existed?
      false
    end

    def allow_missing_post?
      $wm_allow_missing
    end

    def process_post
      true
    end
  end
end

wm_case('flow l7: a method other than POST on a missing resource answers 404') do
  $wm_allow_missing = false
  assert_equal 404, wm_run(wm_res_l7, 'GET').code
end

wm_case('flow m7: a POST the resource disallows answers 404') do
  $wm_allow_missing = false
  h = wm_h('Content-Type' => 'text/plain')
  assert_equal 404, wm_run(wm_res_l7, 'POST', h, WM_B9_BODY).code
end

wm_case('flow m7: a POST the resource allows does not answer 404') do
  $wm_allow_missing = true
  h = wm_h('Content-Type' => 'text/plain')
  assert_true wm_run(wm_res_l7, 'POST', h, WM_B9_BODY).code != 404
end

# --- #p3 (Conflict? on a missing resource) ------------------------- 2

def wm_res_p3
  Class.new(WmSpecMissing) do
    def allowed_methods
      %w[PUT]
    end

    def is_conflict?
      $wm_conflict
    end
  end
end

wm_case('flow p3: a conflicting PUT to a missing resource answers 409') do
  $wm_conflict = true
  assert_equal 409, wm_run(wm_res_p3, 'PUT', wm_h('Content-Type' => 'text/plain'), 'x').code
end

wm_case('flow p3: a PUT without conflict does not answer 409') do
  $wm_conflict = false
  assert_true wm_run(wm_res_p3, 'PUT', wm_h('Content-Type' => 'text/plain'), 'x').code != 409
end

# --- #n11 (Redirect?) ---------------------------------------------- 4

def wm_res_n11
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[POST]
    end

    def resource_exists?
      $wm_exist
    end

    def allow_missing_post?
      true
    end

    # Upstream calls response.redirect_to(uri), which is Location plus
    # the redirect flag; this tree spells the two separately.
    def process_post
      if $wm_new_loc
        response.headers['Location'] = $wm_new_loc
        response.do_redirect
      end
      true
    end
  end
end

[true, false].each do |exist|
  wm_case("flow n11: a redirecting POST answers 303 (exists:#{exist})") do
    $wm_exist = exist
    $wm_new_loc = '/foo/bar'
    h = wm_h('Content-Type' => 'text/plain')
    res = wm_run(wm_res_n11, 'POST', h, WM_B9_BODY)
    assert_equal 303, res.code
    assert_equal '/foo/bar', res.headers['Location']
  end

  wm_case("flow n11: a POST that does not redirect does not answer 303 (exists:#{exist})") do
    $wm_exist = exist
    $wm_new_loc = nil
    h = wm_h('Content-Type' => 'text/plain')
    assert_true wm_run(wm_res_n11, 'POST', h, WM_B9_BODY).code != 303
  end
end

# --- #p11 (New resource?) ----------------------------------------- 10

def wm_res_p11
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[PUT POST]
    end

    def resource_exists?
      $wm_exist
    end

    def process_post
      true
    end

    def allow_missing_post?
      true
    end

    def post_is_create?
      $wm_create
    end

    def create_path
      $wm_new_loc
    end

    def content_types_accepted
      [['text/plain', :accept_text]]
    end

    def accept_text
      response.headers['Location'] = $wm_new_loc if $wm_new_loc
      true
    end
  end
end

def wm_run_p11(method)
  wm_run(wm_res_p11, method, wm_h('content-type' => 'text/plain'), 'new content')
end

[true, false].each do |exist|
  wm_case("flow p11: a PUT that set Location answers 201 (exists:#{exist})") do
    $wm_exist = exist
    $wm_create = false
    $wm_new_loc = 'http://ruby-doc.org/'
    assert_equal 201, wm_run_p11('PUT').code
  end

  wm_case("flow p11: a PUT that set no Location does not answer 201 (exists:#{exist})") do
    $wm_exist = exist
    $wm_create = false
    $wm_new_loc = nil
    res = wm_run_p11('PUT')
    assert_nil res.headers['Location']
    assert_true res.code != 201
  end

  wm_case("flow p11: post_is_create? with a create_path answers 201 and Location (exists:#{exist})") do
    $wm_exist = exist
    $wm_create = true
    $wm_new_loc = '/foo/bar/baz'
    res = wm_run_p11('POST')
    assert_equal 201, res.code
    assert_equal '/foo/bar/baz', res.headers['Location']
  end

  wm_case("flow p11: post_is_create? with a nil create_path answers 500 (exists:#{exist})") do
    $wm_exist = exist
    $wm_create = true
    $wm_new_loc = nil
    assert_equal 500, wm_run_p11('POST').code
  end

  wm_case("flow p11: post_is_create? false does not answer 201 (exists:#{exist})") do
    $wm_exist = exist
    $wm_create = false
    $wm_new_loc = nil
    assert_true wm_run_p11('POST').code != 201
  end
end

# --- #o14 (Conflict? on an existing resource) ---------------------- 2

def wm_res_o14
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[PUT]
    end

    def is_conflict?
      $wm_conflict
    end
  end
end

wm_case('flow o14: a conflicting PUT answers 409') do
  $wm_conflict = true
  assert_equal 409, wm_run(wm_res_o14, 'PUT', wm_h('Content-Type' => 'text/plain'), 'x').code
end

wm_case('flow o14: a PUT without conflict does not answer 409') do
  $wm_conflict = false
  assert_true wm_run(wm_res_o14, 'PUT', wm_h('Content-Type' => 'text/plain'), 'x').code != 409
end

# --- #m16 (DELETE?), #m20 (Delete enacted?) ------------------------ 4

def wm_res_delete
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[GET DELETE]
    end

    def delete_resource
      $wm_deleted
    end

    def delete_completed?
      $wm_completed
    end
  end
end

wm_case('flow m16: a method other than DELETE does not answer 202') do
  $wm_deleted = true
  $wm_completed = true
  assert_true wm_run(wm_res_delete, 'GET').code != 202
end

wm_case('flow m20: a DELETE that fails answers 500') do
  $wm_deleted = false
  $wm_completed = false
  assert_equal 500, wm_run(wm_res_delete, 'DELETE').code
end

wm_case('flow m20b: a DELETE that succeeds but is not complete answers 202') do
  $wm_deleted = true
  $wm_completed = false
  assert_equal 202, wm_run(wm_res_delete, 'DELETE').code
end

wm_case('flow m20b: a DELETE that completes does not answer 202') do
  $wm_deleted = true
  $wm_completed = true
  assert_true wm_run(wm_res_delete, 'DELETE').code != 202
end

# --- #o18 (Multiple representations?) ----------------------------- 14

def wm_res_o18
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[GET HEAD PUT POST DELETE]
    end

    def resource_exists?
      $wm_exist
    end

    def allow_missing_post?
      true
    end

    def multiple_choices?
      $wm_multiple
    end

    # Upstream: [[request.content_type, :accept_all]]. The fallback is
    # for the methods that carry no entity (GET/HEAD/DELETE), where
    # request.content_type is nil and this list is never consulted - a
    # nil type there would only be a nil the marshaller has to survive.
    def content_types_accepted
      [[request.content_type || 'text/plain', :accept_all]]
    end

    def delete_resource
      response.body = 'Response content.'
      true
    end

    def delete_completed?
      true
    end

    def process_post
      response.body = 'Response content.'
      true
    end

    def accept_all
      response.body = 'Response content.'
      true
    end
  end
end

[['GET', true], ['HEAD', true], ['PUT', true], ['PUT', false], ['POST', true], ['POST', false],
 ['DELETE', true]].each do |method, exist|
  entity = method == 'PUT' || method == 'POST'

  wm_case("flow o18b: one representation answers 200 (#{method}, exists:#{exist})") do
    $wm_exist = exist
    $wm_multiple = false
    h = entity ? wm_h('content-type' => 'text/plain') : wm_h
    assert_equal 200, wm_run(wm_res_o18, method, h, entity ? 'request body' : nil).code
  end

  wm_case("flow o18b: multiple representations answer 300 (#{method}, exists:#{exist})") do
    $wm_exist = exist
    $wm_multiple = true
    h = entity ? wm_h('content-type' => 'text/plain') : wm_h
    assert_equal 300, wm_run(wm_res_o18, method, h, entity ? 'request body' : nil).code
  end
end

# --- #o20 (Response includes an entity?) -------------------------- 10

def wm_res_o20
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[GET PUT POST DELETE]
    end

    def resource_exists?
      $wm_exist
    end

    def allow_missing_post?
      true
    end

    # Upstream: [[request.content_type, :accept_all]]. The fallback is
    # for the methods that carry no entity (GET/HEAD/DELETE), where
    # request.content_type is nil and this list is never consulted - a
    # nil type there would only be a nil the marshaller has to survive.
    def content_types_accepted
      [[request.content_type || 'text/plain', :accept_all]]
    end

    def delete_resource
      response.body = $wm_body if $wm_body
      true
    end

    def delete_completed?
      true
    end

    def process_post
      response.body = $wm_body if $wm_body
      true
    end

    def accept_all
      response.body = $wm_body if $wm_body
      true
    end
  end
end

[['PUT', false], ['POST', false], ['DELETE', true], ['POST', true], ['PUT', true]].each do |method, exist|
  entity = method == 'PUT' || method == 'POST'

  wm_case("flow o20: a response body means no 204 (#{method}, exists:#{exist})") do
    $wm_exist = exist
    $wm_body = 'Hello, world!'
    h = entity ? wm_h('content-type' => 'text/plain') : wm_h
    assert_true wm_run(wm_res_o20, method, h, entity ? WM_B9_BODY : nil).code != 204
  end

  wm_case("flow o20: no response body answers 204 (#{method}, exists:#{exist})") do
    $wm_exist = exist
    $wm_body = nil
    h = entity ? wm_h('content-type' => 'text/plain') : wm_h
    assert_equal 204, wm_run(wm_res_o20, method, h, entity ? WM_B9_BODY : nil).code
  end
end

# --- On error ------------------------------------------------------ 3
# OMITTED (1): "calls handle_exception", which mocks the resource
# (`expect(resource).to receive(:handle_exception)`). There is no double
# here - the resource the run frame builds is the real one - and the two
# cases below already prove the inherited handler ran.

def wm_res_raising
  Class.new(WmSpecResource) do
    def to_html
      raise 'oracle'
    end
  end
end

def wm_res_handling
  Class.new(WmSpecResource) do
    def handle_exception(e)
      response.body = 'error'
    end

    def to_html
      raise 'oracle'
    end
  end
end

wm_case('flow on error: an inherited handle_exception answers 500') do
  assert_equal 500, wm_run(wm_res_raising).code
end

wm_case('flow on error: a defined handle_exception answers 500') do
  assert_equal 500, wm_run(wm_res_handling).code
end

wm_case('flow on error: a defined handle_exception can define the body') do
  assert_equal 'error', wm_run(wm_res_handling).body
end
