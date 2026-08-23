// The machine without the reactor (#173): the bytes of an HTTP/1.1
// request go in, the response bytes come out, and no socket exists
// anywhere below this line. It is the Ring's App contract (feed / more
// / pending / on_tick) served out of memory, and nothing more - there
// is no run(), no accept, no read, no poll. Whoever owns the bytes
// calls feed and gets the answer appended.
//
// The value is the CUT, not the code: this header reaches http1.hpp
// and stops there, so a translation unit that embeds the machine never
// sees ring.hpp or liburing.h. mrbgem.rake walks this include closure
// at build time and refuses a build where that stops being true.
#ifndef WEBMACHINE_EMBED_HPP
#define WEBMACHINE_EMBED_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "http1.hpp"

namespace webmachine {

class Embedded {
 public:
  // The app belongs to the caller: ONE Http1 builds every response
  // once and serves any number of connections, exactly as it does
  // under the Ring. `listener` is the App's "whose connection is
  // this". `packetized` is the #147 gate a real TCP accept would
  // supply from the Ring's listener table; an embedder has no socket
  // at all, so there is no proxy sitting behind it to make the unix
  // case apply - true is the caller's normal case, but it is theirs to
  // override.
  explicit Embedded(Http1& app, uint8_t listener = 0, bool packetized = true)
      : app_(app) { st_.reset(listener, packetized); }

  // Feed wire bytes; whatever the machine answers is APPENDED to out.
  // False = this connection is over once out has been written, which
  // is the caller's business - only the caller has anything to close.
  // A connection already over refuses further bytes by name rather
  // than feeding a machine that has said it is done.
  bool feed(const char* data, size_t len, std::string& out) {
    if (!open_) return false;
    app_.on_tick();  // the Ring's per-wake hook; a feed is this loop's wake
    open_ = app_.feed(st_, data, len, out);
    drain(out);
    return open_;
  }

  // Does the connection still owe bytes? Under the Ring this shapes
  // one send flag (MSG_MORE, #168). Here it is feed's post-condition:
  // a fed connection owes nothing, because drain ran to the floor.
  bool owes() const { return app_.pending(st_); }

 private:
  // The delivery continuation (#168) from memory. The Ring hands it
  // out when a send COMPLETES, so a round that produced no bytes would
  // have been no send and gets no continuation - that is this loop's
  // floor, not a guard bolted onto one. A source answers in POINTERS
  // to bytes that already exist; copying them here is the one copy the
  // kernel would otherwise make out of the mapping on send.
  void drain(std::string& out) {
    for (;;) {
      const size_t had = out.size();
      Http1::Plan plan {};
      if (!app_.more(st_, out, plan)) open_ = false;
      if (plan.nseg != 0) {
        // The plan carries the round's wire ORDER, and its sink
        // segments name bytes more() has already appended - so the
        // round is laid out again here, from both sources, instead of
        // pointed-at bytes being tacked on at the end (which would put
        // an h2 DATA payload after the header of the frame AFTER it).
        // This model copies by contract (#173: bytes in, bytes out);
        // the Ring is where pointers stay pointers.
        const std::string tail = out.substr(had);
        out.resize(had);
        for (unsigned i = 0; i < plan.nseg; i++) {
          const Http1::Plan::Seg& sg = plan.seg[i];
          if (sg.base != nullptr) {
            out.append(sg.base, sg.len);
          } else {
            out.append(tail.data() + (sg.off - had), sg.len);
          }
        }
      }
      if (out.size() == had) return;
    }
  }

  Http1& app_;
  Http1::Conn st_;
  bool open_ = true;
};

}  // namespace webmachine

#endif
