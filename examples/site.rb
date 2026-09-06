# The dynamic half of examples/site: three fragments, one event stream,
# one websocket. The pages, the stylesheet, htmx and the photographs are
# files in the asset pack, and the server sends those without a Ruby
# call - see examples/site/README.md for how to build the pack and how
# to start the two together.

# --- GET /fragment/time -----------------------------------------------
# The smallest htmx answer there is: an element, not a page.
class TimeFragment < Webmachine::Resource
  MONTHS = %w[January February March April May June July August September
              October November December].freeze

  # mruby's Time has no strftime, so the clock is spelled here.
  def self.clock(t)
    format('%02d:%02d:%02d', t.hour, t.min, t.sec)
  end

  def to_html
    now = Time.now
    "<span class=\"state up\">#{TimeFragment.clock(now)} on the server, " \
      "#{now.day} #{MONTHS[now.month - 1]} #{now.year}</span>"
  end
end

# --- GET /fragment/search?q= ------------------------------------------
# A list the client filters by asking. No index, no database: the point
# is the round trip, and the answer is the <li> elements themselves.
class SearchFragment < Webmachine::Resource
  SUBJECTS = [
    'a ship at anchor, 1015',
    'a river between rocks, 1016',
    'a road under cloud, 1018',
    'a book on a table, 1024',
    'a sea wall at dusk, 1039',
    'a forest road, 1043',
    'the sea from a hill',
    'a bridge over water'
  ].freeze

  def to_html
    q = request.query['q'].to_s.downcase
    return '' if q.empty?

    hits = SUBJECTS.select { |s| s.include?(q) }
    return '<li class="state">nothing matches that</li>' if hits.empty?

    hits.map { |s| "<li>#{s}</li>" }.join
  end
end

# --- GET|POST|DELETE /fragment/count ----------------------------------
# One number, held by the server. POST raises it, DELETE clears it, and
# every one of the three answers the number as htmx wants it: as the new
# content of the element that asked.
class CountFragment < Webmachine::Resource
  COUNT = [0]

  def allowed_methods
    %w[GET HEAD POST DELETE]
  end

  def post_is_create?
    false
  end

  def process_post
    COUNT[0] += 1
    response.body = to_html
    true
  end

  def delete_resource
    COUNT[0] = 0
    true
  end

  def delete_completed?
    true
  end

  def to_html
    "<strong>#{COUNT[0]}</strong> so far"
  end
end

# --- GET /fragment/photos?page=N --------------------------------------
# A row of pictures, and the marker that asks for the row after it. The
# server decides where the list ends, so the page needs to know nothing
# about how many photographs there are.
class PhotoFragment < Webmachine::Resource
  PHOTOS = [
    %w[p1015.jpg a\ ship\ at\ anchor],
    %w[p1016.jpg a\ river\ between\ rocks],
    %w[p1018.jpg a\ road\ under\ cloud],
    %w[p1024.jpg a\ book\ on\ a\ table],
    %w[p1039.jpg a\ sea\ wall\ at\ dusk],
    %w[p1043.jpg a\ forest\ road]
  ].freeze
  PER_PAGE = 2

  def to_html
    page = request.query['page'].to_i
    page = 1 if page < 1
    first = (page - 1) * PER_PAGE
    slice = PHOTOS[first, PER_PAGE] || []
    return '' if slice.empty?

    out = ''
    slice.each_with_index do |(file, caption), i|
      last = i == slice.size - 1 && first + slice.size < PHOTOS.size
      # htmx swaps this element for the next row when it is scrolled to.
      more = last ? " hx-get=\"/fragment/photos?page=#{page + 1}\" " \
                    'hx-trigger="revealed" hx-swap="afterend"' : ''
      out << "<figure#{more}>" \
             "<img src=\"/img/#{file}\" width=\"800\" height=\"500\" " \
             "alt=\"#{caption}\" loading=\"lazy\">" \
             "<figcaption>#{caption} - #{file}</figcaption>" \
             '</figure>'
    end
    out
  end
end

# --- GET /events ------------------------------------------------------
# One line a second, forever, with an id the browser sends back as
# Last-Event-ID when it reconnects.
class Ticker < Webmachine::SseResource
  def self.heartbeat
    15.s
  end

  def initialize
    @n = request.headers['last-event-id'].to_i
  end

  def on_tick
    @n += 1
    { event: 'tick', id: @n.to_s, data: "#{TimeFragment.clock(Time.now)} tick" }
  end
end

# --- /ws --------------------------------------------------------------
# What the page sends comes back, numbered. "bye" closes the socket.
class Echo < Webmachine::WebsocketResource
  def self.permessage_deflate?
    true
  end

  def initialize
    @seen = 0
  end

  def on_data(data, binary)
    return :close if data.chomp == 'bye'

    @seen += 1
    "#{@seen}: #{data}"
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route %w[fragment time], TimeFragment
    app.add_route %w[fragment search], SearchFragment
    app.add_route %w[fragment count], CountFragment
    app.add_route %w[fragment photos], PhotoFragment
    app.add_sse ['events'], Ticker
    app.add_websocket ['ws'], Echo
  end
end
