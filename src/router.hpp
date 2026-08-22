// The router (#116): ONE constant table per application, marshalled at
// setup out of the token arrays route.add was handed, walked once per
// request. No Ruby object is touched again after add_route returns -
// the tokens live here as bytes and offsets, and matching is memcmp
// over a flat table.
//
// The table is protocol-free on purpose: h1 (Http1::feed, the phr
// request-target) and h2 (Http1::h2_dispatch, the :path pseudo-header)
// walk the SAME table in the SAME registration order, so a route
// cannot mean two things depending on which wire carried it.
#ifndef WEBMACHINE_ROUTER_HPP
#define WEBMACHINE_ROUTER_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace webmachine {

// How many bindings one route may carry. A route past this refuses at
// add_route BY NAME, so the match loop below never has to test.
inline constexpr size_t kMaxRouteBindings = 16;

// What a match CAPTURED: the request bytes a Symbol token bound, and
// the splat's tail. Nothing reads them yet.
//
// They exist already because the capture is where the cost would be:
// the match loop has the segment boundaries in registers exactly once,
// while it is walking. Slice 4 (the lazy Request object) turns these
// spans into Ruby values ON DEMAND, inside the run frame, for the
// resources that ask - and a resource that never asks pays for two
// pointer stores that the loop was going to compute anyway. Adding the
// capture later would mean walking the path a second time, which is
// the one shape this router exists to avoid.
//
// NO member initializers, deliberately: this is scratch the match loop
// fills in, and a declaration at the top of a request path would
// otherwise zero 16 spans - 256 bytes of stores per request that
// nothing reads. A successful match sets nbind, has_splat and whatever
// it captured; a miss (-1) leaves all of it indeterminate, and the
// caller has nothing to read on a miss anyway.
struct RouteSpans {
  struct Span {
    const char* p;
    size_t n;
  };
  Span bind[kMaxRouteBindings];
  Span splat;
  uint8_t nbind;
  bool has_splat;
};

class RouteTable {
 public:
  enum Kind : uint8_t { kLiteral, kBinding, kSplat };

  // --- building (add_route only) ------------------------------------
  // A route under construction. abandon() rolls it back whole, so a
  // route that fails validation leaves NOTHING half-registered.
  void open() {
    pending_first_ = toks_.size();
    pending_blob_ = blob_.size();
    pending_binds_ = 0;
    pending_splat_ = false;
  }
  // False: the literal is longer than a token can address.
  bool literal(const char* p, size_t n) {
    if (n > 0xffffu) return false;
    RouteToken t;
    t.kind = kLiteral;
    t.off = static_cast<uint32_t>(blob_.size());
    t.len = static_cast<uint32_t>(n);
    blob_.append(p, n);
    toks_.push_back(t);
    return true;
  }
  // False: past kMaxRouteBindings - refused by name at add_route.
  bool binding() {
    if (pending_binds_ >= kMaxRouteBindings) return false;
    pending_binds_++;
    toks_.push_back(RouteToken{kBinding, 0, 0});
    return true;
  }
  void splat() {
    pending_splat_ = true;
    toks_.push_back(RouteToken{kSplat, 0, 0});
  }
  bool pending_splat() const { return pending_splat_; }
  void commit() {
    Route r;
    r.first = static_cast<uint32_t>(pending_first_);
    r.count = static_cast<uint32_t>(toks_.size() - pending_first_);
    routes_.push_back(r);
  }
  void abandon() {
    toks_.resize(pending_first_);
    blob_.resize(pending_blob_);
  }

  size_t size() const { return routes_.size(); }
  bool empty() const { return routes_.empty(); }

  // --- matching (per request) ---------------------------------------
  // The FIRST route that matches wins (registration order, exactly
  // what route.add promised). -1 = miss; the caller answers 404 from
  // its prebuilt store, before B13 and before any method test.
  int match(const char* path, size_t len, RouteSpans& out) const {
    // RFC 9110 4.2.1: the query is NOT part of the path. It comes off
    // here, once, before any route is compared - the asset tier reads
    // the target the same way (assets.cpp).
    size_t plen = len;
    for (size_t i = 0; i < len; i++) {
      if (path[i] == '?') {
        plen = i;
        break;
      }
    }
    size_t start = 0;
    if (start < plen && path[start] == '/') start++;
    const char* blob = blob_.data();
    const size_t n = routes_.size();
    for (size_t r = 0; r < n; r++) {
      const Route& rt = routes_[r];
      size_t p = start;
      uint8_t nb = 0;
      bool ok = true;
      bool splat = false;
      for (uint32_t t = 0; t < rt.count; t++) {
        const RouteToken& tk = toks_[rt.first + t];
        if (tk.kind == kSplat) {
          // :* is the last token by construction (add_route refuses
          // anything else), so the rest of the path IS the tail -
          // including the empty tail, which is why /fizz matches
          // ['fizz', :*] as well as /fizz/a/b does.
          out.splat.p = path + p;
          out.splat.n = plen - p;
          p = plen;
          splat = true;
          break;
        }
        if (p >= plen) {
          ok = false;
          break;
        }
        const size_t seg = p;
        while (p < plen && path[p] != '/') p++;
        const size_t seglen = p - seg;
        if (tk.kind == kLiteral) {
          if (seglen != tk.len || std::memcmp(path + seg, blob + tk.off, seglen) != 0) {
            ok = false;
            break;
          }
        } else {
          out.bind[nb].p = path + seg;
          out.bind[nb].n = seglen;
          nb++;
        }
        if (p < plen) p++;  // step over the '/'
      }
      if (!ok) continue;
      // Without a splat every segment must have been spoken for -
      // /fizz/buzz is not ['fizz'].
      if (!splat && p < plen) continue;
      out.nbind = nb;
      out.has_splat = splat;
      return static_cast<int>(r);
    }
    return -1;
  }

 private:
  struct RouteToken {
    Kind kind;
    uint32_t off;  // into blob_ (literals only)
    uint32_t len;
  };
  struct Route {
    uint32_t first;
    uint32_t count;
  };
  std::string blob_;  // every literal's bytes, once
  std::vector<RouteToken> toks_;
  std::vector<Route> routes_;
  size_t pending_first_ = 0;
  size_t pending_blob_ = 0;
  size_t pending_binds_ = 0;
  bool pending_splat_ = false;
};

}  // namespace webmachine

#endif
