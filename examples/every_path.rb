# Every way through the flow graph, one route each (#34 names it "all
# resources in all the ways they can be walked").
#
# The graph has 24 terminals and 36 nodes. A benchmark or a profile that
# only ever asks for a 200 measures one edge of it; this file lets any of
# them be asked for by name:
#
#   REQPATH=/forbidden CONNS=192 APP=examples/every_path.rb bench/floor.sh
#
# Routes whose answer depends on what the client sends are marked; they
# need the header named beside them, and bench/floor.sh's BROWSER=1 or an
# explicit --header is how it gets there.
#
# bintest/every_path.rb drives all of them and checks the status, so a
# route that stops producing its terminal is a failing test, not a
# surprise in a profile.

BODY = '<html><body>every path</body></html>'

# --- 200, and the callbacks a plain answer still runs -----------------
# Kept on the instance on purpose: /ok is the run-tier baseline that
# /reads-request and /writes-response are measured against.
class Ok < Webmachine::Resource
  def to_html
    BODY
  end
end

# --- 503 b13 service_available? ---------------------------------------
class Unavailable < Webmachine::Resource
  def self.service_available?
    false
  end

  def self.to_html
    BODY
  end
end

# --- 501 b12 known_methods --------------------------------------------
class KnownOnly < Webmachine::Resource
  def self.known_methods
    %w[GET HEAD]
  end

  def self.to_html
    BODY
  end
end

# --- 414 b11 uri_too_long? --------------------------------------------
class UriTooLong < Webmachine::Resource
  def self.uri_too_long?(_uri)
    true
  end

  def self.to_html
    BODY
  end
end

# --- 405 b10 allowed_methods (ask with POST) --------------------------
class GetOnly < Webmachine::Resource
  def self.allowed_methods
    %w[GET HEAD]
  end

  def self.to_html
    BODY
  end
end

# --- 400 b9b malformed_request? ---------------------------------------
class Malformed < Webmachine::Resource
  def self.malformed_request?
    true
  end

  def self.to_html
    BODY
  end
end

# --- 401 b8 is_authorized? --------------------------------------------
class Unauthorized < Webmachine::Resource
  def self.is_authorized?(_header)
    false
  end

  def self.to_html
    BODY
  end
end

# --- 403 b7 forbidden? ------------------------------------------------
class Forbidden < Webmachine::Resource
  def self.forbidden?
    true
  end

  def self.to_html
    BODY
  end
end

# --- 501 b6 valid_content_headers? ------------------------------------
class BadContentHeaders < Webmachine::Resource
  def self.valid_content_headers?(_headers)
    false
  end

  def self.to_html
    BODY
  end
end

# --- 415 b5 known_content_type? ---------------------------------------
class BadType < Webmachine::Resource
  def self.known_content_type?(_type)
    false
  end

  def self.to_html
    BODY
  end
end

# --- 413 b4 valid_entity_length? --------------------------------------
class TooLarge < Webmachine::Resource
  def self.valid_entity_length?(_length)
    false
  end

  def self.to_html
    BODY
  end
end

# --- 406 c4, and f6/f7 through a konst encodings_provided -------------
class Negotiate < Webmachine::Resource
  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  # languages_provided / charsets_provided are refused outright by the
  # fold - no i18n or charset conversion exists in this tree - and
  # encodings_provided is konst-only, so it is asked once at setup.
  def self.encodings_provided
    { 'identity' => :identity }
  end

  def self.variances
    %w[Accept-Language]
  end

  def self.to_html
    BODY
  end

  def self.to_json
    '{"every":"path"}'
  end
end

# --- 304 / 412, g8..l17 (ask with If-None-Match / If-Match) -----------
class Conditional < Webmachine::Resource
  UPDATED = 1_756_000_000

  def self.generate_etag
    'every-path-1'
  end

  def self.last_modified
    UPDATED
  end

  def self.expires
    UPDATED + 86_400
  end

  def self.to_html
    BODY
  end
end

# --- 404 g7 false, k7 false -------------------------------------------
class Missing < Webmachine::Resource
  def self.resource_exists?
    false
  end

  def self.to_html
    BODY
  end
end

# --- 410 k7 true, gone ------------------------------------------------
class Gone < Webmachine::Resource
  def self.resource_exists?
    false
  end

  def self.previously_existed?
    true
  end

  def self.to_html
    BODY
  end
end

# --- 301 k5/i4 moved_permanently? -------------------------------------
class MovedPermanently < Webmachine::Resource
  def self.resource_exists?
    false
  end

  def self.previously_existed?
    true
  end

  def self.moved_permanently?
    'http://example.invalid/moved'
  end

  def self.to_html
    BODY
  end
end

# --- 307 l5 moved_temporarily? ----------------------------------------
class MovedTemporarily < Webmachine::Resource
  def self.resource_exists?
    false
  end

  def self.previously_existed?
    true
  end

  def self.moved_temporarily?
    'http://example.invalid/elsewhere'
  end

  def self.to_html
    BODY
  end
end

# --- 300 o18b multiple_choices? ---------------------------------------
class Choices < Webmachine::Resource
  def self.multiple_choices?
    true
  end

  def self.to_html
    BODY
  end
end

# --- 202 m20b delete_completed? false (ask with DELETE) ---------------
class DeleteAccepted < Webmachine::Resource
  def self.allowed_methods
    %w[GET HEAD DELETE]
  end

  def delete_resource
    true
  end

  def self.delete_completed?
    false
  end

  def self.to_html
    BODY
  end
end

# --- 204 the same, completed and with no body (ask with DELETE) -------
class DeleteDone < Webmachine::Resource
  def self.allowed_methods
    %w[GET HEAD DELETE]
  end

  def delete_resource
    true
  end

  def self.to_html
    BODY
  end
end

# --- 201 n11 post_is_create? + create_path (ask with POST) ------------
class Created < Webmachine::Resource
  reads_body :create_path
  reads_body :content_types_accepted
  def self.allowed_methods
    %w[GET HEAD POST]
  end

  def self.post_is_create?
    true
  end

  def create_path
    'created/1'
  end

  def self.content_types_accepted
    [['application/x-www-form-urlencoded', :from_form]]
  end

  def from_form
    true
  end

  def self.to_html
    BODY
  end
end

# --- 303 n11 process_post + do_redirect (ask with POST) ---------------
class SeeOther < Webmachine::Resource
  reads_body :process_post
  def self.allowed_methods
    %w[GET HEAD POST]
  end

  def self.post_is_create?
    false
  end

  def process_post
    response.do_redirect('/ok')
    true
  end

  def self.to_html
    BODY
  end
end

# --- 409 o14/p3 is_conflict? (ask with PUT) ---------------------------
class Conflict < Webmachine::Resource
  reads_body :content_types_accepted
  def self.allowed_methods
    %w[GET HEAD PUT]
  end

  def self.is_conflict?
    true
  end

  def self.content_types_accepted
    [['application/x-www-form-urlencoded', :from_form]]
  end

  def from_form
    true
  end

  def self.to_html
    BODY
  end
end

# --- 500, the error resource's own path -------------------------------
class Boom < Webmachine::Resource
  def to_html
    raise 'every_path: the 500 this route exists to produce'
  end
end

# --- the request API, without changing the terminal -------------------
# Every accessor Resource#request offers, read once. The answer stays a
# 200, so the difference against /ok is what reading the request costs.
class ReadsRequest < Webmachine::Resource
  def to_html
    r = request
    parts = [
      r.method, r.uri, r.path, r.disp_path, r.path_info.size.to_s,
      r.path_tokens.size.to_s, r.query.size.to_s, r.query_string,
      r.headers.size.to_s, (r.body ? r.body.size : 0).to_s, r.has_body?.to_s,
      r.content_type.to_s, r.content_length.to_s, r.authorization.to_s,
      r.accept.to_s, r.accept_encoding.to_s, r.if_match.to_s,
      r.if_none_match.to_s, r.if_modified_since.to_s,
      r.if_unmodified_since.to_s, r.host.to_s, r.cookies.size.to_s,
      r.base_uri, r.get?.to_s, r.head?.to_s, r.post?.to_s, r.put?.to_s,
      r.delete?.to_s, r.options?.to_s
    ]
    "<html><body>#{parts.size} read</body></html>"
  end
end

# --- the response API, same shape -------------------------------------
class WritesResponse < Webmachine::Resource
  def to_html
    response.headers['X-Every-Path'] = 'yes'
    response.set_cookie('every', 'path', path: '/', max_age: '60',
                                         secure: true, httponly: true)
    BODY
  end

  def finish_request
    response.headers['X-Finished'] = 'yes'
    nil
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route ['ok'], Ok
    app.add_route ['unavailable'], Unavailable
    app.add_route ['known-only'], KnownOnly
    app.add_route ['uri-too-long'], UriTooLong
    app.add_route ['get-only'], GetOnly
    app.add_route ['malformed'], Malformed
    app.add_route ['unauthorized'], Unauthorized
    app.add_route ['forbidden'], Forbidden
    app.add_route ['bad-content-headers'], BadContentHeaders
    app.add_route ['bad-type'], BadType
    app.add_route ['too-large'], TooLarge
    app.add_route ['negotiate'], Negotiate
    app.add_route ['conditional'], Conditional
    app.add_route ['missing'], Missing
    app.add_route ['gone'], Gone
    app.add_route ['moved-permanently'], MovedPermanently
    app.add_route ['moved-temporarily'], MovedTemporarily
    app.add_route ['choices'], Choices
    app.add_route ['delete-accepted'], DeleteAccepted
    app.add_route ['delete-done'], DeleteDone
    app.add_route ['created'], Created
    app.add_route ['see-other'], SeeOther
    app.add_route ['conflict'], Conflict
    app.add_route ['boom'], Boom
    app.add_route ['reads-request'], ReadsRequest
    app.add_route ['writes-response'], WritesResponse
  end
end
