// WebSocket, round one's second half (#175): a connection that has
// stopped being HTTP. src/websocket.hpp is the protocol (bytes in,
// bytes out, no state); this is the part that holds a peer - message
// assembly, the control-frame duties RFC 6455 puts on an endpoint, and
// the resource the route named.
//
// THE SURFACE (Nutzer-Entscheid 2026-08-22): a websocket route names a
// Webmachine::WebsocketResource, and that class stands on its OWN -
// it is NOT a Webmachine::Resource. Almost nothing of HTTP survives
// the upgrade: there is no response, no status, no flow, no content
// negotiation. What survives is the handshake's HEAD, so that is the
// one thing a websocket resource can ask for (`request`, headers and
// the route's own bindings included). A base class that inherited the
// flow's would have promised all the rest.
//
// It is instantiated ONCE, like every other resource in this tree, and
// then FED - methods, no block, no proc:
//
//     class Echo < Webmachine::WebsocketResource
//       def on_open                     # optional
//         # `request` is live here - the handshake's head: the subprotocol,
//         # an Origin check, a token in the query are decided from the
//         # handshake's own head. nil accepts; a String accepts AND is
//         # the Sec-WebSocket-Protocol answer; a Symbol refuses the
//         # upgrade with an HTTP status.
//       end
//
//       def on_data(data, binary)       # required
//         data                          # a String goes back to the client
//       end
//
//       def on_close(code, reason)      # optional
//       end
//     end
//
// Every callback's arity is read ONCE at fold: `def on_data(data)`
// and `def on_data(data, binary)` are both called correctly, and
// nothing is passed that the method did not ask for.
//
// PING AND PONG ARE NOT AN API (Nutzer-Entscheid): a ping is answered
// with a pong here, in C, because RFC 6455 5.5.2 makes that the
// endpoint's duty and not an application decision; an incoming pong is
// silent. A resource never sees either.
//
// Three more konst answers, asked once at fold and free per message:
//
//     def self.max_message = 8 * 1024 * 1024   # default 64 KiB
//     def self.validate_text? = false          # default true
//     def self.permessage_deflate? = true      # default false
//
// validate_text? off means this endpoint stops checking incoming TEXT
// messages against RFC 6455 8.1 - faster on a link whose payloads are
// known good, and a peer sending broken text then gets an answer
// instead of the 1007 the RFC asks for.
//
// permessage_deflate? on means this route ACCEPTS RFC 7692 when a
// client offers it. Off by default, and the default is the honest one:
// the extension costs about 296 KiB of zlib per compressing peer
// (wsdeflate.hpp does the arithmetic), on a tree whose connection
// capacity is derived in the tens of thousands. A route that talks to
// browsers over a metered link wants it; a route fanning out to
// thousands of idle sockets does not, and neither should have to find
// that out from a memory graph. Nothing else about the route changes:
// on_data still gets the message, whole and decompressed.
//
// What the method RETURNS is the whole protocol between Ruby and this
// layer:
//   String  - sent to the client, in the SAME kind the message arrived
//             in (a binary message is answered binary, a text message
//             text) - so an echo is `data` and nothing else.
//   Symbol  - an RFC-relevant answer: a close code by name, or a
//             control frame. ws_symbol_action below is the whole list.
//   nil     - nothing is said. A callback that only DID something (a
//             write elsewhere, a counter) says nothing by falling off
//             its own end.
// Anything else closes the connection with 1011 and says why on
// stderr: a return value nobody can spell is a bug in the resource,
// not a message to guess at.
//
// Per-connection Ruby state: NONE. The resource is one instance for
// the whole process, the message is one String per delivery, and a
// connection costs this layer a carry buffer and a few bytes of
// assembly state. Http1 knows only the two opaque pointers below - it
// never learns what a resource is, exactly as it never learned what a
// Resource is (http1.hpp declares resource_run and nothing else).
#ifndef WEBMACHINE_WSCONN_HPP
#define WEBMACHINE_WSCONN_HPP

#include <mruby.h>

#include <cstddef>
#include <string>

#include "wsdeflate.hpp"

namespace webmachine {

// HOW BIG A MESSAGE MAY GET, which is the same question as "how big an
// mruby String may this layer build" - every delivered message is one
// String copied into the GC heap.
//
// The default is small on purpose. A whole message arriving in ONE
// frame is never buffered here: it goes straight from the receive pool
// into that one String, so it costs one copy. A FRAGMENTED message is
// assembled first, so its peak is two copies - and both are PER
// CONNECTION, of which there are as many as the derived capacity
// allows (tens of thousands since #169). A megabyte times that is not
// a number a peer should get to choose.
//
// A route that knows better says so, once, as a class method - the
// same shape the flow's konst callbacks have, read at fold, free per
// message:
//
//     def self.max_message = 8 * 1024 * 1024
//
// Past whatever stands, the close is 1009, which is the code RFC 6455
// 7.4.1 has for exactly this.
inline constexpr size_t kMaxWsMessageDefault = 64u * 1024;

// The route's resource, folded ONCE at route.websocket: the class
// frozen, its one instance built, on_data resolved. Nothing is looked
// up per message and nothing can be redefined behind an open socket.
struct WsResource;

// One peer: what is left of a connection that stopped being HTTP.
struct WsConn;

// Folds a resource class for a websocket route. False leaves the
// reason in err by name (not a Webmachine::WebsocketResource, no
// on_data, a raise while instantiating).
bool ws_fold(mrb_state* mrb, mrb_value klass, WsResource& out, char* err, size_t errlen);

// Does this route accept RFC 7692 at all? Asked by the handshake
// BEFORE it parses a Sec-WebSocket-Extensions offer, so a route that
// says no never pays for the parse.
bool ws_wants_deflate(const WsResource* r);
WsResource* ws_resource_new();
void ws_resource_free(WsResource* r);

// Webmachine::WebsocketResource. Defined at gem init, BEFORE the
// request object (which hangs its accessor on this class as well as on
// Resource - the head is what both kinds of resource read).
void ws_init(mrb_state* mrb, struct RClass* wm);

// The handshake's own half, BEFORE the 101 goes out: runs on_open (if
// there is one) while `request` is still bound, and says whether this
// upgrade happens. True with `proto` empty = plain upgrade; non-empty
// = that is the Sec-WebSocket-Protocol answer. False leaves in
// `status` the HTTP status the resource named instead of an upgrade.
bool ws_admit(const WsResource* r, std::string& proto, uint16_t& status);

// The upgrade is answered: build the peer, with whatever
// permessage-deflate negotiation settled on (wsdeflate.hpp). Params
// with `on` false is a plain RFC 6455 connection and costs nothing.
WsConn* ws_open(const WsResource* r, const wsdeflate::Params& deflate);

// Wire bytes for an upgraded connection. False = this connection ends
// once the sink has drained, exactly like Http1::feed's contract.
// `data` is UNMASKED IN PLACE (websocket.hpp says why): the buffer the
// Ring lends is this process's own pool.
bool ws_feed(WsConn* c, const char* data, size_t len, std::string& sink);

void ws_free(WsConn* c);

}  // namespace webmachine

#endif
