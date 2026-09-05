// The reactor: one io_uring, one thread, every connection.
//
// It lives HERE and not in webmachine.hpp because it is a template on
// the application type, so it has to be a header - and only four
// translation units instantiate one. The other nineteen read
// webmachine.hpp and were paying for 2159 lines they never name.
#ifndef WEBMACHINE_RING_HPP
#define WEBMACHINE_RING_HPP

#include "webmachine.hpp"

namespace webmachine {

template <class App>
class Ring {
 public:
  // One reactor, one io backend, no globals.
  explicit Ring(App& app) : app_(app) {}
  Ring(const Ring&) = delete;
  Ring& operator=(const Ring&) = delete;

  // The ring exit is what ends surviving connections, and what unlinks a
  // unix listener's path.
  ~Ring() {
    for (ktls_keys*& k : tls_keys_) {
      ktls_keys_free(k);
      k = nullptr;
    }
    if (ring_up_) {
      close_listeners();
      unsigned n = 0;
      for (const std::string& path : unix_paths_) {
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) break;
        io_uring_prep_unlink(s, path.c_str(), 0);
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, 0));
        n++;
      }
      if (n != 0) io_uring_submit_and_wait(&ring_, n);
    }
    if (buf_ring_ != nullptr) io_uring_free_buf_ring(&ring_, buf_ring_, kBufCount, kBufGroup);
    if (pool_ != nullptr) ::munmap(pool_, static_cast<size_t>(kBufCount) * kBufSize);
    if (ring_up_) io_uring_queue_exit(&ring_);
  }

  // Everything through the ring: unlink, socket_direct, setsockopt, bind,
  // listen as ONE linked chain, every CQE checked, a failure naming its stage.
  void init(const RingConfig& cfg) {
    mrb_ = cfg.mrb;
    // The one refusal here that cannot raise: there is no VM to raise
    // into. A caller that leaves RingConfig::mrb null is a bug in this
    // tree and not an operator's mistake, so it dies here saying so -
    // and a process that dies is the one case where stderr is read.
    if (mrb_ == nullptr) {
      std::fputs("webmachine: RingConfig::mrb is required - the reactor raises rather than "
                 "ending a process it does not own\n",
                 stderr);
      std::abort();
    }
    int rc = 0;
    raise_memlock();
    constexpr unsigned kSqWanted = 32768;
    constexpr unsigned kSqFloor = 1024;
    constexpr unsigned kSetupFlags =
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    const unsigned sq_wanted = cfg.sq_entries != 0 ? cfg.sq_entries : kSqWanted;
    const unsigned sq_floor = sq_wanted < kSqFloor ? sq_wanted : kSqFloor;
    struct io_uring_params p {};
    for (sq_entries_ = sq_wanted;; sq_entries_ /= 2) {
      p = io_uring_params{};
      p.flags = kSetupFlags;
      rc = io_uring_queue_init_params(sq_entries_, &ring_, &p);
      if (rc == 0) {
        sq_entries_ = p.sq_entries;
        break;
      }
      if (sq_entries_ <= sq_floor) {
        mrb_raisef(mrb_, E_WM_ERROR(mrb_), "io_uring_queue_init(%d): %s",
                   static_cast<int>(sq_entries_), std::strerror(-rc));
      }
    }
    io_uring_register_ring_fd(&ring_);
    ring_up_ = true;

    const uint64_t nofile = raise_nofile();
    log_fd_ = cfg.log_fd;
    err_fd_ = cfg.err_fd;
    backlog_ = cfg.backlog != 0 ? cfg.backlog : SOMAXCONN;
    header_timeout_ = cfg.header_timeout != 0 ? cfg.header_timeout : 60;
    send_timeout_ = cfg.send_timeout != 0 ? cfg.send_timeout : 60;
    idle_timeout_ = cfg.idle_timeout != 0 ? cfg.idle_timeout : 75;
    app_.set_send_timeout(send_timeout_);
    max_conns_ = derive_max_conns({nofile});
    if (max_conns_ == 0) {
      mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                 "RLIMIT_NOFILE %i leaves no room for connections (reserve %d + listeners %d)",
                 static_cast<mrb_int>(nofile), static_cast<int>(kFdReserve),
                 static_cast<int>(kMaxListeners));
    }
    listener_base_ = max_conns_;

    rc = io_uring_register_files_sparse(&ring_, max_conns_ + kMaxListeners);
    if (rc != 0) {
      mrb_raisef(mrb_, E_WM_ERROR(mrb_), "register_files_sparse(%d): %s",
                 static_cast<int>(max_conns_ + kMaxListeners), std::strerror(-rc));
    }
    rc = io_uring_register_file_alloc_range(&ring_, 0, max_conns_);
    if (rc != 0) {
      mrb_raisef(mrb_, E_WM_ERROR(mrb_), "register_file_alloc_range: %s", std::strerror(-rc));
    }

    const size_t pool_bytes = static_cast<size_t>(kBufCount) * kBufSize;
    void* mem =
        ::mmap(nullptr, pool_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
      mrb_raisef(mrb_, E_WM_ERROR(mrb_), "mmap pool: %s", std::strerror(errno));
    }
    pool_ = static_cast<char*>(mem);

    int bre = 0;
    buf_ring_ = io_uring_setup_buf_ring(&ring_, kBufCount, kBufGroup, 0, &bre);
    if (buf_ring_ == nullptr) {
      mrb_raisef(mrb_, E_WM_ERROR(mrb_), "setup_buf_ring: %s", std::strerror(-bre));
    }
    const int mask = io_uring_buf_ring_mask(kBufCount);
    for (uint32_t i = 0; i < kBufCount; i++) {
      io_uring_buf_ring_add(buf_ring_, pool_ + static_cast<size_t>(i) * kBufSize, kBufSize,
                            static_cast<uint16_t>(i), mask, static_cast<int>(i));
    }
    io_uring_buf_ring_advance(buf_ring_, kBufCount);

    bundles_ = (ring_.features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
    if (const char* e = std::getenv("WM_BUNDLE")) {
      if (e[0] == '0') bundles_ = false;
    }

    if (cfg.nlisteners == 0 || cfg.nlisteners > kMaxListeners) {
      mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener count %d out of range (1..%d)",
                 static_cast<int>(cfg.nlisteners), static_cast<int>(kMaxListeners));
    }
    for (uint32_t li = 0; li < cfg.nlisteners; li++) {
      setup_listener(li, cfg.listeners[li]);
      setup_keys(li, cfg.listeners[li]);
    }
    nlisteners_ = cfg.nlisteners;

    conns_ = std::make_unique<Conn[]>(max_conns_);
    live_bits_.assign((static_cast<size_t>(max_conns_) + 63) / 64, 0);
    rearm_.reserve(64);

    if (cfg.stop_fd >= 0) {
      struct io_uring_sqe* s = setup_sqe();
      io_uring_prep_poll_add(s, cfg.stop_fd, POLLIN);
      io_uring_sqe_set_data64(s, detail::tag(detail::kStop, 0, 0));
    }

    for (uint32_t li = 0; li < nlisteners_; li++) arm_accept(li);
  }

  // Every setup step wants an SQE and none of them can go on without one.
  struct io_uring_sqe* setup_sqe() {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (s == nullptr) mrb_raise(mrb_, E_WM_ERROR(mrb_), "SQ empty at setup");
    return s;
  }

  // Loop until the stop signal's completion lands.
  void run() {
    while (!stop_) tick(nullptr);
  }

  // ONE bounded step: the budget bounds the WORK, not just the wait, and
  // the batch is interrupted BETWEEN completions.
  bool tick(const struct __kernel_timespec* budget) {
    if (budget == nullptr) return step(nullptr, false);
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    int64_t deadline = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
    deadline += budget->tv_sec * 1000000000 + budget->tv_nsec;
    return step(&deadline, true);
  }

  // Readable exactly when this ring has completions to hand over.
  int fd() const { return ring_up_ ? ring_.ring_fd : -1; }

  // Did the stop signal's completion land?
  bool stopped() const { return stop_; }


  // Drain, then FORGET: the listeners close at once, and what survives the
  // grace is ended by the destructor's ring exit.
  void drain(int64_t grace_ns) {
    if (draining_) return;
    draining_ = true;
    close_listeners();
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    drain_deadline_ = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec + grace_ns;
    if (live_ == 0 || grace_ns <= 0) stop_ = true;
  }

  // How many accepted connections are still being served.
  uint32_t live_conns() const { return live_; }

  // The derived capacity - what this machine actually allows.
  uint32_t max_conns() const { return max_conns_; }

  // A TCP listener's REAL port, including the kernel's pick for port 0.
  int bound_port(uint32_t li) const { return li < kMaxListeners ? bound_port_[li] : 0; }

 private:
  // One listener as one linked chain; a stale unix path is unlinked OUTSIDE
  // the chain, because ENOENT there is normal.
  void setup_listener(uint32_t li, const ListenerSpec& want) {
    const uint32_t slot = listener_base_ + li;
    const bool is_unix = want.unix_path != nullptr;
    struct sockaddr_un sun {};
    struct sockaddr_in sin {};
    struct sockaddr* sa = nullptr;
    socklen_t salen = 0;
    if (is_unix) {
      sun.sun_family = AF_UNIX;
      const size_t payload_length = std::strlen(want.unix_path);
      if (payload_length >= sizeof(sun.sun_path)) {
        mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener %d: unix path too long (%i)",
                   static_cast<int>(li), static_cast<mrb_int>(payload_length));
      }
      std::memcpy(sun.sun_path, want.unix_path, payload_length + 1);
      sa = reinterpret_cast<struct sockaddr*>(&sun);
      salen = sizeof(sun);

      struct io_uring_sqe* s = setup_sqe();
      io_uring_prep_unlink(s, want.unix_path, 0);
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, 0));
      io_uring_submit_and_wait(&ring_, 1);
      struct io_uring_cqe* cqe = nullptr;
      if (io_uring_peek_cqe(&ring_, &cqe) == 0) {
        if (cqe->res < 0 && cqe->res != -ENOENT) {
          mrb_raisef(mrb_, E_WM_ERROR(mrb_), "unlink %s: %s", want.unix_path,
                     std::strerror(-cqe->res));
        }
        io_uring_cqe_seen(&ring_, cqe);
      }
    } else {
      if (want.port < 0 || want.port > 65535) {
        mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener %d: port %d out of range",
                   static_cast<int>(li), want.port);
      }
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl(INADDR_ANY);
      sin.sin_port = htons(static_cast<uint16_t>(want.port));
      sa = reinterpret_cast<struct sockaddr*>(&sin);
      salen = sizeof(sin);
    }

    static const int kOne = 1;
    unsigned chain = 0;
    {
      struct io_uring_sqe* s = setup_sqe();
      io_uring_prep_socket_direct(s, is_unix ? AF_UNIX : AF_INET, SOCK_STREAM, 0, slot, 0);
      s->flags |= IOSQE_IO_LINK;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStSocket));
      chain++;

      if (!is_unix) {
        s = setup_sqe();
        io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, slot, SOL_SOCKET, SO_REUSEADDR,
                               const_cast<int*>(&kOne), sizeof(kOne));
        s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStSockopt));
        chain++;
      }

      s = setup_sqe();
      io_uring_prep_bind(s, slot, sa, salen);
      s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStBind));
      chain++;

      s = setup_sqe();
      io_uring_prep_listen(s, slot, backlog_);
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStListen));
      chain++;
    }
    io_uring_submit_and_wait(&ring_, chain);
    {
      // Every CQE of the chain has to be seen before anything else can
      // use this ring, so the first failure is kept and raised after the
      // drain rather than in the middle of it.
      std::string failed;
      struct io_uring_cqe* cqe = nullptr;
      while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
        if (cqe->res < 0 && failed.empty()) {
          const uint32_t st = static_cast<uint32_t>(io_uring_cqe_get_data64(cqe));
          failed = cqe->res != -ECANCELED
                       ? std::string(detail::stage_name(st)) + ": " + std::strerror(-cqe->res)
                       : std::string("setup chain canceled");
        }
        io_uring_cqe_seen(&ring_, cqe);
      }
      if (!failed.empty()) {
        mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d %s", static_cast<int>(li),
                   failed.c_str());
      }
    }
    if (is_unix) unix_paths_.emplace_back(want.unix_path);
    unix_listener_[li] = is_unix;

    if (!is_unix) {
      bound_port_[li] = want.port;
      if (want.port == 0) {
        struct sockaddr_storage ss {};
        socklen_t slen = sizeof(ss);
        struct io_uring_sqe* s = setup_sqe();
        io_uring_prep_cmd_getsockname(s, static_cast<int>(slot),
                                      reinterpret_cast<struct sockaddr*>(&ss), &slen, 0);
        s->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStName));
        io_uring_submit_and_wait(&ring_, 1);
        struct io_uring_cqe* cqe = nullptr;
        int res = -EIO;
        if (io_uring_peek_cqe(&ring_, &cqe) == 0) {
          res = cqe->res;
          io_uring_cqe_seen(&ring_, cqe);
        }
        if (res < 0) {
          mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                     "listener %d: port 0 needs the bound port read back and this kernel "
                     "cannot (SOCKET_URING_OP_GETSOCKNAME: %s) - name a port",
                     static_cast<int>(li), std::strerror(-res));
        }
        if (ss.ss_family == AF_INET) {
          bound_port_[li] = ntohs(reinterpret_cast<struct sockaddr_in*>(&ss)->sin_port);
        } else if (ss.ss_family == AF_INET6) {
          bound_port_[li] = ntohs(reinterpret_cast<struct sockaddr_in6*>(&ss)->sin6_port);
        } else {
          mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d: bound name family %d?",
                     static_cast<int>(li), static_cast<int>(ss.ss_family));
        }
      }
    }
  }

  // NO RFC - one slot of the reactor, so what the kernel touches carries
  // the kernel's names (rule 4: the ARGUMENT a field becomes) and what
  // only we touch says that it is ours:
  //   meminfo   getsockopt(fd, SOL_SOCKET, SO_MEMINFO, optval, optlen)
  //   addr,     accept4/getsockname(fd, addr, addrlen) - and what
  //   addrlen   Http1::Conn::peer then points into
  //   msg       struct msghdr, handed to io_uring_prep_sendmsg
  //   msg_iov,  its msg_iov and msg_iovlen, filled from an App::Plan
  //   msg_iovlen
  //   gen       ours: the generation half of user_data's tag, which is
  //             what makes a reused slot safe
  //   out/next  ours: the round on the wire and the one being built
  //
  // Ordered by alignment, not by topic - see Http1::Conn's own note. The
  // flags sat between the 8-byte members and cost 21 bytes of padding.
  struct Conn {
    int64_t deadline_s = 0;
    // #30: when the watcher this connection's stopped run waits on has
    // been quiet for as long as it allowed. 0 = nothing is armed. It is
    // NOT deadline_s: the peer on this socket is fine, some other
    // descriptor is the quiet one, and nothing here closes anything.
    int64_t w_deadline_s = 0;

    static constexpr size_t kRoundFloor = 64u * 1024;
    size_t round_cap = kRoundFloor;
    // The kernel writes all of these, so the landing buffer is full size
    // even though on_meminfo reads three of them. Every accept arms it,
    // so it stays inline - a pointer here would be a malloc per
    // connection to save 36 bytes.
    uint32_t meminfo[SK_MEMINFO_VARS] = {};

    // The peer's address, materialised only where it is going to be
    // read. arm_peer runs for a logged TCP connection and nothing else,
    // so a unix listener - and every server started without --log -
    // carries a null pointer here instead of a sockaddr_storage, which
    // is 128 bytes of which __ss_padding is 118. Kept for the slot's
    // life once made, like FileIo below and for the same reason:
    // Http1::Conn::peer points into it, and reset() clears peer_len
    // rather than the pointer.
    struct PeerAddr {
      socklen_t addrlen = 0;
      struct sockaddr_storage addr {};
    };
    std::unique_ptr<PeerAddr> peer;

    std::string out;
    std::string next;

    // response.file's one in-flight open. Lazy like everything else here -
    // most connections never open a file, and `struct statx` alone is ~256
    // bytes that used to sit inline on every slot regardless. Allocated on
    // first use (arm_file_open, right after app_.file_take() says a file is
    // actually wanted) and kept for the slot's life rather than freed on
    // every close: it "outlives a torn-down connection by one completion"
    // (see file_reading below), so tearing it down on close would race that
    // in-flight completion.
    //
    // unique_ptr, not a raw pointer, and for the same reason iov below
    // already is one: conns_ is a std::vector, and a raw pointer
    // plus a hand-written destructor would delete the implicit move
    // constructor a vector resize needs, falling back to a copy - which a
    // unique_ptr member refuses to compile, exactly like iov already
    // refuses it. unique_ptr keeps the move and needs no
    // destructor of its own.
    // NO RFC - this is the kernel's ABI, so the fields carry the names of
    // the ARGUMENTS they become:
    //
    //   io_uring_prep_read(sqe, fd, buf + filled, nbytes - filled,
    //                      offset + filled)
    //   io_uring_prep_statx(sqe, fd, "", AT_EMPTY_PATH, mask, &stx)
    //
    // Two of them are not arguments and say so.
    struct FileIo {
      // A PLAIN fd, not a direct descriptor: statx is the only op in this
      // chain the kernel does not accept a fixed file for, and statting the
      // OPENED fd (AT_EMPTY_PATH) is what keeps size and mtime describing
      // the bytes that were actually confined - a statx by path would
      // resolve a second time, unguarded.
      int fd = -1;
      // Not an argument: how much of `nbytes` has arrived. A read may come
      // back short, so the next one resumes at buf + filled.
      size_t filled = 0;
      size_t nbytes = 0;
      // Where in the FILE this window starts. Earlier windows advanced it,
      // so the kernel gets offset + filled and stx_size ends the chain.
      size_t offset = 0;
      size_t stx_size = 0;
      // Not an argument: a read whose buffer the App still owns. It
      // outlives a torn-down connection by one completion, so nothing may
      // hand that buffer back or resize it while this stands.
      bool reading = false;
      struct statx stx {};
    };
    std::unique_ptr<FileIo> file_io;

    // Not ABI: our own ceiling, one segment more than a Plan can hold, for
    // the head that rides in front of it - and the kernel's own UIO_MAXIOV.
    // It is what a round may NEVER exceed, not what a connection carries.
    //
    // What a round actually plans, counted: an h1 answer that lends takes
    // THREE segments (the head out of the sink, and a gzip member's two
    // halves out of the mapping), an h2 one nine. The ceiling is reachable
    // only by heavy multiplexing. So the common case rides inline and
    // costs no allocation at all, and the heap is for the round that does
    // not fit - see take_plan.
    //
    // FOUR and not sixteen: this is paid by every slot the FD budget
    // allows, live or not (conns_.resize(max_conns_)), so each entry is
    // 16 bytes times ~19k here. Four covers h1's three; h2 takes one heap
    // array on a connection that already carries an H2State.
    static constexpr unsigned kMsgIovMax = App::Plan::kSegs + 1;
    static constexpr unsigned kMsgIovInline = 4;
    size_t plan_byte_total = 0;
    struct msghdr msg {};

    unsigned msg_iovlen = 0;
    // How many segments the CURRENT store has room for. A high-water mark,
    // because the slot outlives the connection and a grown array is the
    // answer to the next round on it as well.
    unsigned msg_iov_cap = kMsgIovInline;
    // How much of `out` the kernel has already taken. Only ever non-zero
    // on an offloaded connection, which is the only one that resumes a
    // send; everywhere else MSG_WAITALL makes one send the whole round.
    // A plan resumes by advancing its own iovecs - see plan_drop_front.
    size_t out_sent = 0;
    uint16_t gen = 0;
    uint8_t listener = 0;
    bool live = false;
    bool sending = false;
    bool close_after_send = false;
    bool idle = false;

    typename App::Conn app;

    // Where the resolved iovecs live: inline until a round needs more,
    // heap from then on. `iov()` is the one way to reach them.
    struct iovec msg_iov_inline[kMsgIovInline];
    std::unique_ptr<struct iovec[]> msg_iov_heap;
    struct iovec* iov() { return msg_iov_heap ? msg_iov_heap.get() : msg_iov_inline; }

    // Everything TLS on this connection, and nothing on a connection that
    // is not one - most servers run a plaintext listener beside the TLS
    // one, and a cleartext slot pays a pointer.
    //
    // The exchange is freed the moment the keys are copied out: it holds
    // an OpenSSL SSL and its buffers, which is the largest thing this
    // process would otherwise carry per connection, and after the
    // handover there is nothing left for it to do. What outlives it is
    // `info`, because the setsockopt the kernel is still working on
    // points into it.
    struct Tls {
      ktls_exchange* x = nullptr;
      // The two crypto_info blobs, copied out of the exchange. The
      // largest is ChaCha20-Poly1305: 12 iv, 32 key, 0 salt, 8 rec_seq
      // plus the 4-byte header.
      unsigned char info[2][64] = {};
      size_t info_len[2] = {};
      // recvmsg needs a msghdr that outlives the submit, and a multishot
      // one outlives many completions; the kernel reads namelen and
      // controllen out of it to size what it writes into each buffer.
      struct msghdr recv_msg {};
      // RFC 8446 6.1's close_notify, kept here for the same reason as
      // recv_msg: it is submitted and then waited for, so the header,
      // the control buffer and the alert itself all outlive the call
      // that spelled them.
      struct msghdr bye_msg {};
      struct iovec bye_iov {};
      unsigned char bye[2] = {1, 0};  // warning, close_notify
      unsigned char bye_control[CMSG_SPACE(1)] = {};
      // RFC 8446 4.6.1: plaintext a peer put in the same flight as its
      // Finished. The kernel's stream starts at sequence zero and cannot
      // be handed a backlog, so this waits here until the socket has both
      // keys and then goes to the App ahead of anything the wire brings.
      std::string early;
      // RFC 8446 5.5, counted here because after the handover the kernel
      // writes the records and does not count for us. What we know is
      // what we fed it: every send is at least one record and at most
      // ceil(len / 16384), and the larger of those is what is charged,
      // so the rekey comes early rather than late. Zero limit - ChaCha -
      // never charges anything.
      uint64_t tx_records = 0;
      uint64_t tx_limit = 0;
      bool handshaking = true;
      bool offloaded = false;
      ~Tls() { ktls_exchange_free(x); }
    };
    std::unique_ptr<Tls> tls;
  };

  // The reactor cannot go on, and it is not this library's place to
  // decide what that means for the process - it is embedded, and the
  // process belongs to somebody else. So it raises, and the embedder's
  // Ruby sees Webmachine::Error and chooses. There is no second branch:
  // init() refuses a RingConfig without a VM, so this always has one.
  // A failure that belongs to ONE connection. It throws, and the
  // completion handler below catches it, says what happened and closes
  // that connection - the process belongs to somebody else, so one
  // peer's bad day is not its end (fatal, below, is for when it is).
  //
  // `what` is always a string literal: the once-only reporting keys on
  // the pointer, so two calls with the same literal are the same fault.
  struct ConnFailed {
    const char* what;
    int err;  // a negative errno where the kernel gave one, 0 where it did not
  };
  [[noreturn]] static void conn_failed(const char* what, int err = 0) {
    throw ConnFailed{what, err};
  }

  // The error log is where these belong, and with a peer to name they
  // carry it. Without a log they fall to stderr - and there once per
  // distinct reason, so a peer that can provoke one cannot provoke a
  // line per attempt.
  void say_connection_failed(const ConnFailed& f, const Conn& c) {
    const std::string why =
        f.err < 0 ? std::string(f.what) + ": " + std::strerror(-f.err) : std::string(f.what);
    Logger* el = app_.error_log();
    if (el != nullptr && el->enabled) {
      log_internal_error(
          *el, {c.peer != nullptr
                    ? std::string_view{reinterpret_cast<const char*>(&c.peer->addr),
                                       static_cast<size_t>(c.peer->addrlen)}
                    : std::string_view{},
                {},
                why,
                0});
      return;
    }
    for (unsigned i = 0; i < said_count_; i++) {
      if (said_[i] == f.what) return;
    }
    if (said_count_ < kSaidMax) said_[said_count_++] = f.what;
    std::fprintf(stderr, "webmachine: %s (said once)\n", why.c_str());
  }

  [[noreturn]] void fatal(const char* what) {
    mrb_raise(mrb_, E_WM_ERROR(mrb_), what);
    // mruby declares mrb_raise mrb_noreturn, but that macro (common.h)
    // resolves to NOTHING under -std=c++20: it asks for __GNUC__ &&
    // !__STRICT_ANSI__, and a strict -std= (rather than -std=gnu=) defines
    // __STRICT_ANSI__. So the compiler cannot see what is true either way -
    // with MRB_USE_CXX_EXCEPTION the raise throws, without it it longjmps -
    // and warns that a [[noreturn]] function returns. This says it instead.
    __builtin_unreachable();
  }

  // The same, with the sentence built by mruby instead of by a 160-byte
  // buffer on the way to it. %d, %i, %s and %v are mrb_format's, not
  // printf's - there is no length modifier left to get wrong.
  template <typename... Args>
  [[noreturn]] void fatalf(const char* fmt, Args... args) {
    mrb_raisef(mrb_, E_WM_ERROR(mrb_), fmt, args...);
    __builtin_unreachable();
  }

  // Never null on return: a full SQ is drained by submitting it, and the
  // retry then has room. io_uring_enter(2) can refuse that submit, and
  // its ANSWER is the thing worth reading - EINTR and EAGAIN are ordinary
  // and retried, EBUSY means the CQ is full and completions must be
  // reaped before anything else can go in, which this call cannot do
  // re-entrantly. Ignoring the answer, as this did, turned a recoverable
  // ring into "broken" and then killed the process over it.
  struct io_uring_sqe* sqe() {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (WM_LIKELY(s != nullptr)) return s;
    for (int attempt = 0; attempt < 8; attempt++) {
      const int rc = io_uring_submit(&ring_);
      if (rc < 0 && rc != -EINTR && rc != -EAGAIN) {
        fatalf("SQ (%d entries) full and io_uring_enter refused it: %s",
               static_cast<int>(sq_entries_), std::strerror(-rc));
      }
      s = io_uring_get_sqe(&ring_);
      if (WM_LIKELY(s != nullptr)) return s;
    }
    fatalf("SQ (%d entries) stuck after 8 submits", static_cast<int>(sq_entries_));
  }

  static constexpr uint32_t kStreamAccess = 0;
  static constexpr uint32_t kStreamError = 1;

  // Both streams, once per round, riding the submit that was happening anyway.
  void flush_log() {
    flush_access();
    flush_error();
  }

  // The whole batch in ONE send: small, constant-shaped records.
  void flush_access() {
    if (log_fd_ < 0) return;
    Logger* al = app_.access_log();
    if (al == nullptr || al->in_flight || al->pending.empty()) return;
    al->pending.swap(al->flight);
    al->in_flight = true;
    arm_access_write(al);
  }
  // send, not write: a dead daemon must be -EPIPE in a CQE, not a SIGPIPE.
  void arm_access_write(Logger* al) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_send(s, log_fd_, al->flight.data(), al->flight.size(), MSG_NOSIGNAL);
    io_uring_sqe_set_data64(s, detail::tag(detail::kLog, 0, kStreamAccess));
  }

  // ONE record per flush, as two linked sends.
  void flush_error() {
    if (err_fd_ < 0) return;
    Logger* el = app_.error_log();
    if (el == nullptr || el->in_flight || el->pending.size() < sizeof(ErrRec)) return;
    ErrRec r;
    std::memcpy(&r, el->pending.data(), sizeof r);
    const size_t whole = sizeof(ErrRec) + r.dynamic_len;
    if (el->pending.size() < whole) return;
    el->flight.assign(el->pending, 0, whole);
    el->pending.erase(0, whole);
    el->in_flight = true;
    arm_error_write(el);
  }
  // MSG_WAITALL is what makes the LINK safe: IO_LINK breaks only on FAILURE,
  // and a short send is not one.
  void arm_error_write(Logger* el) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_send(s, err_fd_, el->flight.data(), sizeof(ErrRec),
                       MSG_NOSIGNAL | MSG_WAITALL);
    s->flags |= IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kLog, 1, kStreamError));
    s = sqe();
    io_uring_prep_send(s, err_fd_, el->flight.data() + sizeof(ErrRec),
                       el->flight.size() - sizeof(ErrRec), MSG_NOSIGNAL | MSG_WAITALL);
    io_uring_sqe_set_data64(s, detail::tag(detail::kLog, 0, kStreamError));
  }

  // THE RULE: every line formatted lands. A refused write is a named refusal.
  void on_log(uint16_t gen, uint32_t stream, struct io_uring_cqe* cqe) {
    Logger* lg = stream == kStreamError ? app_.error_log() : app_.access_log();
    if (lg == nullptr) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      if (stream == kStreamError && cqe->res == -ECANCELED) return;
      fatalf("%s log write failed: %s - refusing to drop lines",
             stream == kStreamError ? "error" : "access", std::strerror(-cqe->res));
    }
    if (stream == kStreamError) {
      if (gen == 1) return;
      lg->flight.clear();
      lg->in_flight = false;
      return;
    }
    const size_t took = static_cast<size_t>(cqe->res);
    if (WM_UNLIKELY(took < lg->flight.size())) {
      lg->flight.erase(0, took);
      arm_access_write(lg);
      return;
    }
    lg->flight.clear();
    lg->in_flight = false;
  }

  // The certificate a TLS listener answers with, and the two suites this
  // build speaks. Once per listener, at boot: every exchange this
  // listener ever opens is opened from it.
  // ktls_keys is a C handle: every refusal below unwinds past it now, so
  // its free belongs to a destructor and not to a line before each of
  // four returns.
  struct HeldKeys {
    ktls_keys* k = nullptr;
    explicit HeldKeys(ktls_keys* keys) : k(keys) {}
    ~HeldKeys() {
      if (k != nullptr) ktls_keys_free(k);
    }
    HeldKeys(const HeldKeys&) = delete;
    HeldKeys& operator=(const HeldKeys&) = delete;
    ktls_keys* release() {
      ktls_keys* const out = k;
      k = nullptr;
      return out;
    }
  };

  void setup_keys(uint32_t li, const ListenerSpec& want) {
    if (want.cert_pem == nullptr) return;
    // The certificate BEFORE the kernel, deliberately: both can be wrong
    // at once, and the one the operator can fix is the one worth saying.
    // It also means a machine without the module still checks the config.
    HeldKeys keys{ktls_keys_server(want.cert_pem, want.cert_len, want.key_pem, want.key_len)};
    if (keys.k == nullptr) {
      mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener %d certificate: %s",
                 static_cast<int>(li), ktls_last_error());
    }
    // AES first where the machine has the instructions, ChaCha first
    // otherwise (.DESIGN.md "Two suites, and why not three"). Said out
    // loud because it decides whether a NIC can ever take the record
    // layer over, and because it is not otherwise visible from outside.
    const bool aes_is_fast = ktls_aes_is_fast();
    std::fprintf(stderr, "webmachine: listener %u offers %s first (aes instructions: %s)\n", li,
                 aes_is_fast ? "TLS_AES_128_GCM_SHA256" : "TLS_CHACHA20_POLY1305_SHA256",
                 aes_is_fast ? "yes" : "no");
    const char* suites = aes_is_fast
                             ? "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
                             : "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    if (ktls_keys_set_ciphers(keys.k, suites) != 0) {
      mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d ciphers: %s", static_cast<int>(li),
                 ktls_last_error());
    }
    // Both, in preference order. Nothing downstream reads the answer:
    // RFC 9113 3.4's preface is the first thing an h2 client sends, and
    // Http1::feed_parse already decides on it - over TLS those bytes
    // arrive exactly as they do in the clear.
    static const char* const kProtocols[] = {"h2", "http/1.1"};
    if (ktls_keys_set_alpn(keys.k, kProtocols, 2) != 0) {
      mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d alpn: %s", static_cast<int>(li),
                 ktls_last_error());
    }
    if (!ktls_available()) {
      const int rc = ktls_load_module();
      if (rc != 0 || !ktls_available()) {
        mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                   "listener %d serves TLS and this kernel has no tls ULP (modprobe tls): %s",
                   static_cast<int>(li), ktls_last_error());
      }
    }
    tls_keys_[li] = keys.release();
  }

  // The listeners leave through the ring; idempotent, or a later accept
  // would lose its slot.
  void close_listeners() {
    if (listeners_closed_) return;
    listeners_closed_ = true;
    for (uint32_t i = 0; i < nlisteners_; i++) {
      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) break;
      io_uring_prep_close_direct(s, listener_base_ + i);
      io_uring_sqe_set_data64(s, detail::tag(detail::kClose, 0, listener_base_ + i));
    }
    io_uring_submit(&ring_);
  }

  // Multishot accept_direct against the fixed listener slot.
  void arm_accept(uint32_t li) {
    if (draining_) return;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_multishot_accept_direct(s, listener_base_ + li, nullptr, nullptr, 0);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kAccept, 0, li));
  }

  // Room for the ONE cmsg an offloaded socket carries, TLS_GET_RECORD_TYPE.
  static constexpr size_t kTlsCmsgSpace = CMSG_SPACE(sizeof(unsigned char));

  // Multishot recv out of the buffer ring, bundles where the kernel offers
  // them - and two other shapes for a connection that is doing TLS.
  void arm_recv(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    if (WM_UNLIKELY(c.tls != nullptr)) {
      if (!c.tls->offloaded) {
        // ONE completion at a time while the exchange runs. The moment it
        // is done this process must stop reading: bytes it takes off the
        // socket after that are records the kernel's own record layer is
        // about to be made responsible for, and nothing here could decrypt
        // them once the exchange is freed. A multishot recv has no pause,
        // so the handshake does not use one.
        io_uring_prep_recv(s, static_cast<int>(idx), nullptr, 0, 0);
        s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
        s->buf_group = kBufGroup;
        io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
        return;
      }
      // Offloaded: never a plain recv (.DESIGN.md "Never a plain recv on an
      // offloaded socket"). A record that is not application data is EIO on
      // recv and a control message on recvmsg. The kernel sizes what it
      // writes into each buffer from these two lengths, so the msghdr has to
      // outlive the submit - it lives in Tls for that reason.
      c.tls->recv_msg = msghdr{};
      c.tls->recv_msg.msg_controllen = kTlsCmsgSpace;
      io_uring_prep_recvmsg_multishot(s, static_cast<int>(idx), &c.tls->recv_msg, 0);
      s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
      s->buf_group = kBufGroup;
      io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
      return;
    }
    io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
    s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    s->buf_group = kBufGroup;
    if (bundles_) s->ioprio |= IORING_RECVSEND_BUNDLE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
  }

  // The handshake, and the only thing this connection does until it is
  // over. mruby-ktls names no descriptor: bytes that arrived go in through
  // feed, bytes that must go out come back through take, and the socket
  // stays the reactor's - so what comes out of here is an ordinary send on
  // the same slot, through the same ring, as everything else.
  void tls_advance(uint32_t idx) {
    Conn& c = conns_[idx];
    ktls_step step = KTLS_READING;
    if (WM_UNLIKELY(ktls_exchange_step(c.tls->x, &step) != 0)) {
      conn_failed("tls: the key exchange failed");
    }
    // Unconditional and after the step, because ktls.h says a step that
    // answers KTLS_READING may still owe bytes.
    std::string& sink = c.sending ? c.next : c.out;
    for (;;) {
      char buf[4096];
      const size_t n = ktls_exchange_take(c.tls->x, buf, sizeof buf);
      if (n == 0) break;
      sink.append(buf, n);
    }
    if (step != KTLS_DONE) {
      // EXACTLY ONE read is armed at a time, and whoever writes last
      // arms it: a flight going out means on_send does, because two
      // reads on one connection would feed the exchange two halves of
      // the peer's next flight in whatever order they completed.
      if (c.sending || !c.out.empty()) {
        if (!c.sending) arm_send(idx);
        return;
      }
      arm_recv(idx);
      return;
    }
    // Everything the exchange still holds is read HERE, in the order
    // ktls.h asks for: the backlog first, because draining it can consume
    // a post-handshake record, and the crypto_info last, because that is
    // where the record sequence is finally settled.
    c.tls->handshaking = false;
    for (;;) {
      char buf[4096];
      const size_t n = ktls_exchange_backlog(c.tls->x, buf, sizeof buf);
      if (n == 0) break;
      c.tls->early.append(buf, n);
    }
    for (int dir = 0; dir < 2; dir++) {
      size_t len = 0;
      const void* info = ktls_crypto_info(c.tls->x, static_cast<ktls_direction>(dir), &len);
      if (WM_UNLIKELY(info == nullptr || len > sizeof c.tls->info[dir])) {
        conn_failed("tls: the agreed keys are not a shape the kernel takes");
      }
      std::memcpy(c.tls->info[dir], info, len);
      c.tls->info_len[dir] = len;
    }
    // The SSL and its buffers go now - the largest thing this process
    // would otherwise carry per connection, and nothing above still reads
    // from them. The exchange itself stays for the connection's life,
    // because the traffic secrets are what answers a KeyUpdate.
    ktls_exchange_release(c.tls->x);

    // The last flight is already TLS records. It has to reach the wire as
    // itself - from the TLS_TX setsockopt on, the kernel encrypts what this
    // process sends, and encrypting them twice is what a peer would see.
    // A send already in flight counts: what it did not take is in c.next.
    if (c.sending || !c.out.empty()) {
      if (!c.sending) arm_send(idx);
      return;
    }
    tls_handover(idx);
  }

  // A key per direction, linked so the order is the kernel's to keep
  // rather than two completions to sort out. The ULP went on at accept.
  // The options go on the DIRECT descriptor through the ring, like every
  // other option this reactor sets.
  void tls_handover(uint32_t idx) {
    Conn& c = conns_[idx];
    if (io_uring_sq_space_left(&ring_) < 2) io_uring_submit(&ring_);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_TX), c.tls->info[KTLS_TX],
                           static_cast<uint32_t>(c.tls->info_len[KTLS_TX]));
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsTx, c.gen, idx));

    s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_RX), c.tls->info[KTLS_RX],
                           static_cast<uint32_t>(c.tls->info_len[KTLS_RX]));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsRx, c.gen, idx));
  }

  // RFC 8446 4.6.3, answered: turn the receive secret one notch and put
  // the new crypto_info on the socket. The kernel restarts that
  // direction's sequence at zero, which is what a key change leaves,
  // and the exchange keeps the secret precisely for this - it is why
  // ktls_exchange_release exists rather than a free.
  //
  // ULP is already on, so this is one option and not a chain, and the
  // read is armed again only once the kernel has the key.
  void tls_next_receive_key(uint32_t idx) {
    Conn& c = conns_[idx];
    if (WM_UNLIKELY(ktls_next_key(c.tls->x, KTLS_RX) != 0)) {
      conn_failed("tls: the key update could not be answered");
    }
    size_t len = 0;
    const void* info = ktls_crypto_info(c.tls->x, KTLS_RX, &len);
    if (WM_UNLIKELY(info == nullptr || len > sizeof c.tls->info[KTLS_RX])) {
      begin_close(idx);
      return;
    }
    std::memcpy(c.tls->info[KTLS_RX], info, len);
    c.tls->info_len[KTLS_RX] = len;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_RX), c.tls->info[KTLS_RX],
                           static_cast<uint32_t>(len));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsRx, c.gen, idx));
  }

  // The last of the three. From here the socket is the kernel's record
  // layer and this connection is an ordinary one again - except that its
  // recv is a recvmsg, and that anything the peer pipelined behind its
  // Finished has been waiting and goes first.
  // One connection, and the slot it lives in - the reactor knows a
  // connection by both and needs both.
  struct Slot {
    uint32_t idx;
    Conn& conn;
  };

  // One completion as the reactor hands it on: the connection slot it
  // names, the generation that slot was in when the op was armed (a slot
  // that has since been reused answers a stale generation, and the
  // completion is dropped), and the CQE itself.
  struct Completed {
    uint32_t idx;
    uint16_t gen;
    struct io_uring_cqe* cqe;
  };

  void on_tls_ready(Completed done) {
    const uint32_t idx = done.idx;
    const uint16_t gen = done.gen;
    struct io_uring_cqe* const cqe = done.cqe;
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen || c.tls == nullptr) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      conn_failed(c.tls->offloaded ? "tls: setsockopt(TLS_RX) for a key update"
                                   : "tls: setsockopt(TLS_RX)",
                  cqe->res);
    }
    // A KeyUpdate lands here too - same option, same completion - and
    // there is no backlog and no deadline to reset for that one.
    if (c.tls->offloaded) {
      arm_recv(idx);
      return;
    }
    c.tls->offloaded = true;
    c.tls->tx_limit = ktls_record_limit(c.tls->x);
    c.tls->tx_records = 0;
    c.deadline_s = now_s_ + header_timeout_;
    // Once per process, and it is the line that says the whole design
    // works: from here this socket's record layer is the kernel's.
    if (!tls_handed_over_said_) {
      tls_handed_over_said_ = true;
      std::fprintf(stderr, "webmachine: tls: a socket is the kernel's now (%s, said once)\n",
                   ktls_exchange_cipher(c.tls->x) != nullptr ? ktls_exchange_cipher(c.tls->x)
                                                             : "?");
    }
    if (!c.tls->early.empty()) {
      std::string early;
      early.swap(c.tls->early);
      deliver(idx, early.data(), early.size(), true);
      if (!c.live) return;
    }
    arm_recv(idx);
  }

  // RFC 8446 5.5: a send is at least one record and at most one per
  // 16384 bytes of it, and the larger is what is charged - the count has
  // to be an over-estimate or it is not a bound.
  static void tls_charge_records(Conn& c, size_t bytes) {
    if (c.tls->tx_limit == 0) return;
    static constexpr size_t kRecordPlaintextMax = 16384;
    const uint64_t records = bytes == 0 ? 1 : (bytes + kRecordPlaintextMax - 1) / kRecordPlaintextMax;
    c.tls->tx_records += records;
  }

  // The send key, turned before the limit rather than after it, and only
  // where no send is in flight - the kernel must not be writing under a
  // key that is being replaced. ktls_record_limit already answers HALF of
  // what the RFC allows, so there is room to get here.
  bool tls_turn_send_key(uint32_t idx) {
    Conn& c = conns_[idx];
    if (c.tls == nullptr || !c.tls->offloaded) return false;
    if (c.tls->tx_limit == 0 || c.tls->tx_records < c.tls->tx_limit) return false;
    if (WM_UNLIKELY(ktls_next_key(c.tls->x, KTLS_TX) != 0)) {
      conn_failed("tls: the send key could not be turned before its record limit");
    }
    size_t len = 0;
    const void* info = ktls_crypto_info(c.tls->x, KTLS_TX, &len);
    if (WM_UNLIKELY(info == nullptr || len > sizeof c.tls->info[KTLS_TX])) {
      conn_failed("tls: the turned send key is not a shape the kernel takes");
    }
    std::memcpy(c.tls->info[KTLS_TX], info, len);
    c.tls->info_len[KTLS_TX] = len;
    c.tls->tx_records = 0;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), ktls_sol_tls(),
                           ktls_optname(KTLS_TX), c.tls->info[KTLS_TX],
                           static_cast<uint32_t>(len));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsTxKey, c.gen, idx));
    return true;
  }

  // The new key is on the socket; the round goes on from where it waited.
  void on_tls_tx_key(Completed done) {
    const uint32_t idx = done.idx;
    const uint16_t gen = done.gen;
    struct io_uring_cqe* const cqe = done.cqe;
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;
    if (WM_UNLIKELY(cqe->res < 0)) conn_failed("tls: setsockopt(TLS_TX) for a record limit", cqe->res);
    send_done(idx);
  }

  // What the kernel took, dropped off the front of a plan: whole segments
  // go, the first partial one is trimmed. Nothing is allocated and
  // nothing copied - the segments that stay point at the same asset
  // mappings and lent Strings they already did.
  static void plan_drop_front(Conn& c, size_t took) {
    unsigned seg = 0;
    struct iovec* const iov = c.iov();
    while (seg < c.msg_iovlen && took >= iov[seg].iov_len) {
      took -= iov[seg].iov_len;
      seg++;
    }
    if (seg < c.msg_iovlen && took != 0) {
      iov[seg].iov_base = static_cast<char*>(iov[seg].iov_base) + took;
      iov[seg].iov_len -= took;
    }
    const unsigned left = c.msg_iovlen - seg;
    for (unsigned i = 0; i < left; i++) iov[i] = iov[seg + i];
    c.msg_iovlen = left;
  }

  // One sendmsg for the round; MSG_MORE when the App still owes bytes.
  //
  // MSG_WAITALL where the kernel takes it: it finishes a short send
  // itself, so the round is one operation and there is no offset to
  // carry. An OFFLOADED connection cannot have it - tls_sw_sendmsg
  // answers EOPNOTSUPP for any flag outside MSG_MORE, MSG_DONTWAIT,
  // MSG_NOSIGNAL, MSG_SPLICE_PAGES and MSG_EOR - so that one asks for no
  // retry and resumes itself, out of `out_sent` or its own iovecs.
  //
  // The lend survives either way: resource.cpp freezes and roots the
  // String and zc_release hands it back when the ROUND drains, never
  // when one send returns.
  void arm_send(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    const bool resumes = c.tls != nullptr && c.tls->offloaded;
    const int flags = MSG_NOSIGNAL | (resumes ? 0 : MSG_WAITALL) |
                      (app_.pending(c.app) ? MSG_MORE : 0);
    if (c.msg_iovlen == 0) {
      io_uring_prep_send(s, static_cast<int>(idx), c.out.data() + c.out_sent,
                         c.out.size() - c.out_sent, flags);
    } else if (c.msg_iovlen == 1 && !resumes) {
      // ONE segment is one buffer, and a buffer does not need an iovec.
      // sendmsg makes the kernel copy an msghdr in from user space and
      // import the vector behind it - io_msg_copy_hdr, io_sendmsg_prep,
      // copy_iovec_from_user, __import_iovec - which a profile of one h1
      // run put at over 8% of everything. send carries a pointer and a
      // length and skips all of it.
      //
      // An offloaded TLS socket keeps sendmsg: send_resume re-points the
      // vector it was given, and that path is not this one to change.
      const struct iovec* const one = c.iov();
      io_uring_prep_send(s, static_cast<int>(idx), one[0].iov_base, one[0].iov_len, flags);
    } else {
      c.msg = msghdr{};
      c.msg.msg_iov = c.iov();
      c.msg.msg_iovlen = c.msg_iovlen;
      io_uring_prep_sendmsg(s, static_cast<int>(idx), &c.msg, flags);
    }
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kSend, c.gen, idx));
    c.sending = true;
  }

  // One bit per slot, so the once-a-second reap can find the live ones
  // without reading a Conn to ask. The table is sized by RLIMIT_NOFILE
  // (derive_max_conns), not by the peers actually here, so walking it
  // touched a cache line per slot however few were connected.
  void live_set(uint32_t idx) { live_bits_[idx >> 6] |= 1ULL << (idx & 63); }
  void live_clear(uint32_t idx) { live_bits_[idx >> 6] &= ~(1ULL << (idx & 63)); }

  // RFC 8446 6.1: without it a peer cannot tell a finished stream from a
  // truncated one. Nothing here builds a record - the kernel does, from
  // the type this control message names - so it is a sendmsg like any
  // other, linked ahead of the shutdown that follows it.
  //
  // Only where the socket already IS the kernel's: before the handover
  // there is no key to encrypt an alert with, and a cleartext one would
  // be noise on the wire.
  void arm_close_notify(uint32_t idx) {
    Conn& c = conns_[idx];
    if (c.tls == nullptr || !c.tls->offloaded) return;
    const int cmsg_type = ktls_record_type_set_cmsg();
    if (WM_UNLIKELY(cmsg_type < 0)) return;

    typename Conn::Tls& t = *c.tls;
    t.bye_iov.iov_base = t.bye;
    t.bye_iov.iov_len = sizeof t.bye;
    t.bye_msg = msghdr{};
    t.bye_msg.msg_iov = &t.bye_iov;
    t.bye_msg.msg_iovlen = 1;
    t.bye_msg.msg_control = t.bye_control;
    t.bye_msg.msg_controllen = sizeof t.bye_control;
    struct cmsghdr* cm = CMSG_FIRSTHDR(&t.bye_msg);
    cm->cmsg_level = ktls_sol_tls();
    cm->cmsg_type = cmsg_type;
    cm->cmsg_len = CMSG_LEN(1);
    if (WM_UNLIKELY(ktls_record_type_encode(KTLS_RECORD_ALERT, CMSG_DATA(cm), 1) != 1)) return;
    t.bye_msg.msg_controllen = CMSG_SPACE(1);

    struct io_uring_sqe* s = sqe();
    io_uring_prep_sendmsg(s, static_cast<int>(idx), &t.bye_msg, MSG_NOSIGNAL);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kTlsBye, c.gen, idx));
  }

  // shutdown BEFORE close_direct, linked: close_direct alone leaves the
  // socket open and the peer never sees FIN.
  void begin_close(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.live) return;
    if (c.sending) {
      c.close_after_send = true;
      return;
    }
    // A transfer dying under a client is exactly the event an operator
    // wants in the log, so the line is owed here too - with the bytes that
    // really went out.
    app_.file_abandon(c.app);
    // The exchange goes now - it is the biggest thing this slot holds and
    // nothing submitted points into it. The struct around it does NOT: a
    // handover's three setsockopts read c.tls->info and a multishot
    // recvmsg writes through c.tls->recv_msg, and either may still be with
    // the kernel. It goes when the slot is accepted into again.
    if (c.tls != nullptr) {
      ktls_exchange_free(c.tls->x);
      c.tls->x = nullptr;
    }
    c.live = false;
    live_clear(idx);
    if (live_ != 0) live_--;
    if (io_uring_sq_space_left(&ring_) < 3) io_uring_submit(&ring_);
    arm_close_notify(idx);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_shutdown(s, static_cast<int>(idx), SHUT_RDWR);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kShutdown, c.gen, idx));
    s = sqe();
    io_uring_prep_close_direct(s, idx);
    io_uring_sqe_set_data64(s, detail::tag(detail::kClose, c.gen, idx));
  }

  // A new peer: its slot, its clocks, and the setsockopts TCP wants.
  void on_accept(uint32_t li, struct io_uring_cqe* cqe) {
    if (!(cqe->flags & IORING_CQE_F_MORE)) arm_accept(li);
    if (cqe->res < 0) return;
    const uint32_t idx = static_cast<uint32_t>(cqe->res);
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    c.gen++;
    c.live = true;
    live_set(idx);
    live_++;
    c.sending = false;
    c.close_after_send = false;
    c.idle = false;
    c.deadline_s = now_s_ + header_timeout_;
    c.listener = static_cast<uint8_t>(li);
    c.out.clear();
    c.out_sent = 0;
    c.next.clear();
    c.app.reset(static_cast<uint8_t>(li), !unix_listener_[li]);
    if (!unix_listener_[li]) {
      static const int kOne = 1;
      struct io_uring_sqe* s = sqe();
      io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx),
                             IPPROTO_TCP, TCP_NODELAY, const_cast<int*>(&kOne), sizeof(kOne));
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, idx));
    }
    // A listener with a certificate hands its peer an exchange before it
    // hands it anything else; arm_recv reads this to know which shape it
    // is submitting, so it is set before the first read is armed.
    c.tls.reset();
    if (WM_UNLIKELY(tls_keys_[li] != nullptr)) {
      c.tls.reset(new typename Conn::Tls());
      c.tls->x = ktls_exchange_open(tls_keys_[li], KTLS_SERVER);
      if (WM_UNLIKELY(c.tls->x == nullptr)) {
        begin_close(idx);
        return;
      }
      // The ULP goes on HERE, not at the handover - the order the kernel
      // documents and the one OpenSSL's own ktls_enable uses. Without
      // keys it forwards bytes unchanged, so the handshake reads and
      // writes exactly as it would have; TLS_TX and TLS_RX are what
      // install the record layer later.
      //
      // At the handover it was too late: tls_init refuses a socket that
      // is not ESTABLISHED, and by then a peer that finished its own
      // handshake and hung up has already put this one in CLOSE_WAIT.
      // Here the accept has just returned, so there is no such window.
      static const char kUlp[] = "tls";
      struct io_uring_sqe* u = sqe();
      io_uring_prep_cmd_sock(u, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx), IPPROTO_TCP,
                             TCP_ULP, const_cast<char*>(kUlp), sizeof kUlp);
      u->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(u, detail::tag(detail::kTlsUlp, c.gen, idx));
    }
    arm_meminfo(idx);
    if (log_fd_ >= 0 && !unix_listener_[li]) arm_peer(idx);
    arm_recv(idx);
  }

  // Wire bytes to the App. Kernel-supplied ids and lengths are checked
  // before use; ENOBUFS re-arms rather than hanging the connection.
  // Nothing arrived that can be parsed: a peer that left, a kernel that
  // ran out of buffers, a completion whose own numbers do not hold. None
  // of it is the path a request takes, so none of it is in one.
  void on_recv_nothing_to_parse(Slot s, struct io_uring_cqe* cqe) {
    const uint32_t idx = s.idx;
    Conn& c = s.conn;
    if (cqe->res == -ENOBUFS) {
      rearm_.push_back(idx);
      return;
    }
    if (cqe->res < 0 && c.tls != nullptr && c.tls->offloaded) {
      conn_failed("tls: recvmsg on an offloaded socket", cqe->res);
    }
    begin_close(idx);
  }

  // Bytes for a connection that has already been told to go: the buffers
  // still have to be handed back, and nothing else does.
  void on_recv_after_close(uint32_t idx, size_t total) {
    (void) idx;
    replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
  }

  void on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (WM_UNLIKELY(!c.live || c.gen != gen)) return;

    if (WM_UNLIKELY(cqe->res <= 0)) {
      on_recv_nothing_to_parse({idx, c}, cqe);
      return;
    }
    if (WM_UNLIKELY(!(cqe->flags & IORING_CQE_F_BUFFER))) {
      begin_close(idx);
      return;
    }
    const uint32_t bid0 = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    const size_t total = static_cast<size_t>(cqe->res);
    if (WM_UNLIKELY(bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize)) {
      begin_close(idx);
      return;
    }
    if (WM_UNLIKELY(c.close_after_send)) {
      on_recv_after_close(idx, total);
      return;
    }
    if (WM_UNLIKELY(c.tls != nullptr)) {
      on_recv_tls(idx, {bid0, total, cqe->flags});
      return;
    }
    if (WM_UNLIKELY(c.idle)) {
      c.idle = false;
      c.deadline_s = now_s_ + header_timeout_;
    }

    std::string& sink = c.sending ? c.next : c.out;
    bool closing = false;
    size_t left = total;
    uint32_t bid = bid0;
    typename App::Plan req;
    req.byte_cap = c.round_cap;
    while (left > 0) {
      const size_t n = left < kBufSize ? left : kBufSize;
      size_t off = 0;
      if (WM_UNLIKELY(__builtin_mul_overflow(static_cast<size_t>(bid),
                                             static_cast<size_t>(kBufSize), &off))) {
        begin_close(idx);
        return;
      }
      const bool last = left <= kBufSize;
      typename App::Plan* plan = (last && !c.sending) ? &req : nullptr;
      if (!closing) closing = !app_.feed(c.app, {pool_ + off, n}, {sink, plan});
      left -= n;
      bid = (bid + 1) & (kBufCount - 1);
      replenish_++;
    }

    if (!c.sending) {
      if (req.iovlen != 0) {
        take_plan(c, req);
        arm_send(idx);
      } else if (!c.out.empty()) {
        arm_send(idx);
      }
    }
    // A run that named a file answered nothing yet: the open is the
    // reactor's, and its result reaches the wire through continue_conn.
    arm_file_open(idx);
    arm_compute_task(idx);
    arm_watchers(idx);
    // Unless the name never reached the kernel at all - a refusal this
    // process spelled itself owes no completion, so nothing else would
    // ever come back to collect it.
    if (WM_UNLIKELY(App::file_answerable(c.app)) && !c.sending) continue_conn(idx);
    if (WM_UNLIKELY(closing)) {
      round_closed(idx, c);
      if (!c.live) return;
    }
    if (WM_UNLIKELY(!(cqe->flags & IORING_CQE_F_MORE))) rearm_.push_back(idx);
  }

  // The App will take nothing more on this connection.
  void round_closed(uint32_t idx, Conn& c) {
    if (c.tls != nullptr && c.tls->offloaded) {
      conn_failed("tls: the parser refused what the kernel decrypted", -EPROTO);
    }
    if (c.sending) c.close_after_send = true;
    else begin_close(idx);
  }

  // What a round owes once the App has seen its bytes: the answer on the
  // wire, an open the run deferred, and the close it may have asked for.
  // Shared, because bytes reach the App from three places - the buffer
  // ring, an offloaded socket's recvmsg, and the backlog a handshake left.
  void finish_round(uint32_t idx, typename App::Plan& req, bool closing) {
    Conn& c = conns_[idx];
    if (!c.sending) {
      if (req.iovlen != 0) {
        take_plan(c, req);
        arm_send(idx);
      } else if (!c.out.empty()) {
        arm_send(idx);
      }
    }
    // A run that named a file answered nothing yet: the open is the
    // reactor's, and its result reaches the wire through continue_conn.
    arm_file_open(idx);
    arm_compute_task(idx);
    // Unless the name never reached the kernel at all - a refusal this
    // process spelled itself owes no completion, so nothing else would ever
    // come back to collect it.
    if (WM_UNLIKELY(App::file_answerable(c.app)) && !c.sending) continue_conn(idx);
    if (WM_UNLIKELY(closing)) round_closed(idx, c);
  }

  // ONE contiguous stretch of plaintext to the App, and the round it
  // finishes. `last` is what lets a Plan form, so a caller that has the
  // whole of what arrived says so.
  void deliver(uint32_t idx, const char* data, size_t len, bool last) {
    Conn& c = conns_[idx];
    typename App::Plan req;
    req.byte_cap = c.round_cap;
    typename App::Plan* plan = (last && !c.sending) ? &req : nullptr;
    std::string& sink = c.sending ? c.next : c.out;
    const bool closing = !app_.feed(c.app, {data, len}, {sink, plan});
    finish_round(idx, req, closing);
  }

  // The same buffers, for a connection doing TLS. Before the handover the
  // bytes are records only the exchange can read; after it they are
  // plaintext the kernel already decrypted, and what they arrive in is a
  // recvmsg's own layout rather than the payload alone.
  // What one recv delivered: the first buffer of the run, how many octets
  // it holds, and the CQE flags that described it.
  struct RecvBytes {
    uint32_t bid0;
    size_t total;
    uint32_t flags;
  };

  void on_recv_tls(uint32_t idx, RecvBytes got) {
    const uint32_t bid0 = got.bid0;
    const size_t total = got.total;
    const uint32_t flags = got.flags;
    Conn& c = conns_[idx];
    const size_t off = static_cast<size_t>(bid0) * kBufSize;
    replenish_++;

    if (c.tls->handshaking) {
      if (WM_UNLIKELY(total > kBufSize || ktls_exchange_feed(c.tls->x, pool_ + off, total) != 0)) {
        conn_failed("tls: the peer's handshake bytes were refused");
      }
      tls_advance(idx);
      return;
    }

    // Between the handshake finishing and the last of the three
    // setsockopts landing, nothing is armed and nothing may arrive - so a
    // completion here belongs to a socket that is already the kernel's.
    struct io_uring_recvmsg_out* o =
        io_uring_recvmsg_validate(pool_ + off, static_cast<int>(total), &c.tls->recv_msg);
    if (WM_UNLIKELY(o == nullptr)) {
      conn_failed("tls: a recvmsg header that does not fit its own buffer");
    }
    // A record whose plaintext did not fit, or a control message that did
    // not. Either would hand the parser a piece of something and call it
    // the whole thing, so neither is read.
    if (WM_UNLIKELY((o->flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)) {
      conn_failed("tls: a record too large for one buffer");
    }
    // An alert or a post-handshake record reaches a plain recv as EIO and
    // nothing else; here it says which it is (.DESIGN.md "Never a plain
    // recv on an offloaded socket").
    ktls_record record = KTLS_RECORD_UNKNOWN;
    for (struct cmsghdr* cm = io_uring_recvmsg_cmsg_firsthdr(o, &c.tls->recv_msg); cm != nullptr;
         cm = io_uring_recvmsg_cmsg_nexthdr(o, &c.tls->recv_msg, cm)) {
      if (cm->cmsg_level == ktls_sol_tls() && cm->cmsg_type == ktls_record_type_cmsg()) {
        record = ktls_record_type(CMSG_DATA(cm), cm->cmsg_len - CMSG_LEN(0));
      }
    }
    if (WM_UNLIKELY(record != KTLS_RECORD_DATA)) {
      // An alert ends the connection because that is what one is for -
      // close_notify included, which is the ordinary way a peer leaves.
      if (record != KTLS_RECORD_HANDSHAKE) {
        if (record == KTLS_RECORD_ALERT) {
          begin_close(idx);
          return;
        }
        conn_failed("tls: a record of no known type");
      }
      tls_next_receive_key(idx);
      return;
    }
    const void* payload = io_uring_recvmsg_payload(o, &c.tls->recv_msg);
    const size_t len =
        io_uring_recvmsg_payload_length(o, static_cast<int>(total), &c.tls->recv_msg);
    if (len != 0) {
      deliver(idx, static_cast<const char*>(payload), len, true);
      if (!c.live) return;
    }
    if (!(flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
  }

  // What the kernel took, and what is still owed.
  void on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    c.sending = false;

    if (WM_UNLIKELY(cqe->res < 0)) {
      send_refused(idx, c, cqe->res);
      return;
    }
    // MSG_WAITALL means the kernel already retried; fewer bytes than offered
    // is a dead peer, and a half-written response cannot be resumed - HTTP/1
    // has no restart point and an h2 frame cut in half breaks the whole
    // connection's framing. So the only answer is to drop it.
    const size_t took = static_cast<size_t>(cqe->res);
    const size_t offered = c.msg_iovlen != 0 ? c.plan_byte_total : c.out.size() - c.out_sent;
    if (WM_UNLIKELY(took != offered)) {
      // Nobody retried this one, so what is left is still owed and the
      // stream carries on where it stopped. That is the one thing a
      // half-written response CAN do; what it cannot do is start again.
      if (WM_UNLIKELY(c.tls != nullptr) && c.tls->offloaded) {
        send_resume(idx, c, took);
        return;
      }
      begin_close(idx);
      return;
    }
    c.deadline_s = now_s_ + send_timeout_;
    if (WM_UNLIKELY(c.tls != nullptr) && c.tls->offloaded) tls_charge_records(c, took);
    c.out.clear();
    c.out_sent = 0;
    c.msg_iovlen = 0;
    c.plan_byte_total = 0;
    // A send key at its record limit is turned HERE, where nothing is in
    // flight; what the round owes next waits for that completion. The
    // null test is at THIS side of the call so a cleartext send does not
    // make one.
    if (WM_UNLIKELY(c.tls != nullptr) && tls_turn_send_key(idx)) return;
    send_done(idx);
  }

  // A send the kernel refused outright.
  void send_refused(uint32_t idx, Conn& c, int err) {
    if (c.tls != nullptr && c.tls->offloaded) {
      conn_failed("tls: send on an offloaded socket", err);
    }
    begin_close(idx);
  }

  // Only an offloaded connection gets here: without MSG_WAITALL nobody
  // retried, so what is left is still owed and the stream carries on
  // where it stopped. That is the one thing a half-written response CAN
  // do; what it cannot do is start again.
  void send_resume(uint32_t idx, Conn& c, size_t took) {
    if (c.msg_iovlen != 0) {
      plan_drop_front(c, took);
      c.plan_byte_total -= took;
    } else {
      c.out_sent += took;
    }
    c.deadline_s = now_s_ + send_timeout_;
    tls_charge_records(c, took);
    arm_send(idx);
  }

  // What a finished send leaves owed: the rest of the round, the next
  // one, or the connection going idle. Inline in on_send, which is the
  // path every response takes; on_tls_tx_key calls it because a rekey
  // happens once per 2^23 records and may pay for the call.
  void send_done(uint32_t idx) {
    Conn& c = conns_[idx];
    // The handshake's own bytes, now on the wire as themselves. Only once
    // nothing is left may the kernel be given the write key.
    if (WM_UNLIKELY(c.tls != nullptr) && !c.tls->offloaded) {
      if (c.next.empty()) {
        if (c.tls->handshaking) arm_recv(idx);
        else tls_handover(idx);
        return;
      }
      c.out.swap(c.next);
      arm_send(idx);
      return;
    }
    if (!c.next.empty()) {
      c.out.swap(c.next);
      arm_send(idx);
      return;
    }
    if (app_.pending(c.app)) {
      arm_meminfo(idx);
      return;
    }
    continue_conn(idx);
  }

  // response.file, stage 1: openat2 against the docroot fd. RESOLVE_BENEATH
  // anchors the walk to THAT fd, so the confinement is the kernel's and not
  // this code's - no path math here, on purpose.
  void arm_file_open(uint32_t idx) {
    Conn& c = conns_[idx];
    // The same shape as arm_compute_task: the answer is no on every
    // round that does not name a file, and file_take is a call into
    // another translation unit to hear it.
    if (WM_LIKELY(!App::file_waiting(c.app))) return;
    if (c.file_io != nullptr && c.file_io->reading) return;  // its buffer is still under a live read
    const char* path = app_.file_take(c.app);
    if (path == nullptr) return;
    if (c.file_io == nullptr) c.file_io.reset(new Conn::FileIo());
    struct io_uring_sqe* s = sqe();
    io_uring_prep_openat2(s, docroot_fd(), path, const_cast<struct open_how*>(docroot_how()));
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileOpen, c.gen, idx));
  }

  // #80: the work a stopped run left, handed to a worker. Started here
  // and not at setup: a server whose resources never stop must not carry
  // threads it will never use, and this runs once for the whole process
  // the first time anything stops.
  // #30: what a stopped run left to wait on. The connection filed each
  // watcher under a slot; this puts a poll on its descriptor with the
  // events it asks for, and the slot rides in the tag.
  //
  // ONE-SHOT, not multishot. A watcher changes what it waits for in the
  // middle of a wait - libpq wants writable while it flushes and
  // readable while it reads, and hiredis says so through addWrite and
  // delWrite - and a one-shot poll is re-armed with the new mask
  // anyway. A multishot would have to be cancelled for every change.
  void arm_watchers(uint32_t idx) {
    Conn& c = conns_[idx];
    int slot = -1;
    while (App::watch_take(c.app, &slot)) arm_watch(idx, c, slot);
  }

  void arm_watch(uint32_t idx, Conn& c, int slot) {
    const int fd = App::watcher_descriptor(c.app, slot);
    const unsigned mask = App::watcher_mask(c.app, slot);
    if (fd < 0 || mask == 0) return;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_poll_add(s, fd, mask);
    io_uring_sqe_set_data64(s, detail::watch_tag(c.gen, idx, static_cast<uint8_t>(slot)));
    App::watcher_is_armed(c.app, slot, &ring_);
    // How long this one may stay quiet. The sweep reads whole seconds,
    // so a fraction becomes the next whole second up - a deadline that
    // fires early is a promise broken, one that fires late is not.
    const double quiet = App::watcher_quiet_seconds(c.app, slot);
    if (quiet > 0.0) {
      const int64_t secs = static_cast<int64_t>(quiet) + (quiet > static_cast<double>(static_cast<int64_t>(quiet)) ? 1 : 0);
      c.w_deadline_s = now_s_ + (secs > 0 ? secs : 1);
    }
  }

  // One readiness for one watcher. The block decides what happens next.
  void on_watch(uint32_t idx, uint16_t gen, uint8_t slot, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;
    // A poll that failed says the descriptor is gone. The block hears
    // nothing more; the run reads nil and answers for it.
    const unsigned revents =
        cqe->res > 0 ? static_cast<unsigned>(cqe->res) : static_cast<unsigned>(POLLERR);
    step_watch(idx, c, static_cast<int>(slot), App::watcher_event(c.app, slot, revents));
  }

  void step_watch(uint32_t idx, Conn& c, int slot, typename App::WatchStep step) {
    switch (step) {
      case App::WatchStep::kWait:
      case App::WatchStep::kRearm:
        // Both arm again - the mask is read fresh either way, so the two
        // differ only in what the reader learns from the name.
        arm_watch(idx, c, slot);
        return;
      case App::WatchStep::kDone:
        c.w_deadline_s = 0;
        App::watchers_drop_slot(c.app, slot);
        if (!c.sending) continue_conn(idx);
        return;
    }
  }

  void arm_compute_task(uint32_t idx) {
    Conn& c = conns_[idx];
    // Almost every round asks and almost none has a job. Ask first, and
    // build nothing until the answer is yes.
    if (WM_LIKELY(!App::compute_task_waiting(c.app))) return;
    if (compute_.workers() == 0) {
      // One per core the process may use, less the reactor's own - and
      // never more VMs than the build allows. Every worker opens an
      // mrb_state, the HAL counts those across the PROCESS, and a VM
      // over the ceiling is refused: the worker then dies, its ring
      // still takes its turn in the round robin, and the jobs sent to it
      // are never answered. On a four-core machine that never showed; on
      // a bigger one every compute task hung.
      const long cores = ::sysconf(_SC_NPROCESSORS_ONLN);
      const unsigned by_core = cores > 1 ? static_cast<unsigned>(cores - 1) : 1;
      const unsigned ceiling = compute_worker_ceiling();
      const unsigned want = by_core < ceiling ? by_core : ceiling;
      if (const char* why = compute_.start(want, kComputeDepth, &ring_)) {
        conn_failed(why, -EAGAIN);
      }
    }
    // #30: a value round hands over several jobs at one stop, and they
    // go to the pool together. The tag carries the job's slot the same
    // way a watcher's does, so each answer finds its own place.
    for (int slot = 0; slot < App::Conn::kJobSlots; slot++) {
      std::string arg;
      unsigned code = 0;
      double deadline = 0.0;
      if (!App::compute_task_take(c.app, slot, &code, arg, &deadline)) continue;
      if (!compute_.submit(code, arg, deadline,
                           detail::compute_task_tag(c.gen, idx, static_cast<uint8_t>(slot)))) {
        // Every slot taken. Not a refusal this layer invents - the run
        // is told, and it answers 503 the way it would answer anything
        // else.
        App::compute_task_refused(c.app);
        if (!c.sending) continue_conn(idx);
        return;
      }
    }
  }

  // The fd leaves through the ring like every other descriptor here.
  void arm_file_close(uint32_t idx, int fd, uint16_t gen) {
    if (fd < 0) return;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_close(s, fd);
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileClose, gen, idx));
  }

  // The head is spelled; `spell_next_round` is what puts it on the wire, so a connection
  // mid-send is left to on_send's own continuation.
  void file_wake(uint32_t idx) {
    if (!conns_[idx].sending) continue_conn(idx);
  }

  // #80: a worker answered. The tag is the CONNECTION's, so the same
  // generation guard every other op relies on discards an answer whose
  // connection is already gone - the run died with the slot, and its
  // frame with it.
  //
  // Nothing is resumed here. The run needs a sink and a plan to write
  // its answer into, and this is not a point where either exists; `spell_next_round`
  // is. So this only says the answer arrived, and takes the same door
  // response.file takes.
  void on_compute_task(uint32_t idx, uint16_t gen, uint8_t slot, struct io_uring_cqe* cqe) {
    (void)cqe;
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    const uint64_t tag = detail::compute_task_tag(gen, idx, slot);
    ComputeAnswer answered;
    const bool have = compute_.take(tag, &answered);
    if (!have) answered.raised = true;
    // A raise inside a worker is the one failure nobody else can see:
    // it happened on another thread, in another VM, and the client only
    // gets a 500. So it goes to the error log whole - class, message,
    // backtrace and which worker - and it goes there even when the
    // connection is gone, because the fault is the application's either
    // way.
    if (answered.raised && !answered.exception_class.empty()) {
      Logger* const el = app_.error_log();
      if (el != nullptr && el->enabled) {
        log_compute_fault(*el, {answered.exception_class, answered.message, answered.backtrace,
                                answered.worker_name,
                                c.live && c.gen == gen && c.peer != nullptr
                                    ? std::string_view{reinterpret_cast<const char*>(&c.peer->addr),
                                                       static_cast<size_t>(c.peer->addrlen)}
                                    : std::string_view{},
                                {}});
      }
    }
    // A generation that moved means the connection is gone and its run
    // died with it. The answer is still TAKEN, because the slot is the
    // pool's and would otherwise stay busy for the life of the process.
    if (!c.live || c.gen != gen) return;
    App::compute_task_answered(c.app, static_cast<int>(slot), answered);
    if (!c.sending) continue_conn(idx);
  }

  // ENOENT, EXDEV (RESOLVE_BENEATH), ELOOP (RESOLVE_NO_SYMLINKS), EACCES -
  // ONE answer for all of them, so probing for a symlink or a traversal
  // cannot be told apart from asking for a name that was never there.
  void on_file_open(Completed done) {
    const uint32_t idx = done.idx;
    const uint16_t gen = done.gen;
    struct io_uring_cqe* const cqe = done.cqe;
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) {
      arm_file_close(idx, cqe->res >= 0 ? cqe->res : -1, gen);
      return;
    }
    if (cqe->res < 0) {
      app_.file_reject(c.app);
      file_wake(idx);
      return;
    }
    c.file_io->fd = cqe->res;
    c.file_io->filled = 0;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_statx(s, c.file_io->fd, "", AT_EMPTY_PATH,
                        STATX_TYPE | STATX_SIZE | STATX_MTIME, &c.file_io->stx);
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileStat, c.gen, idx));
  }

  // statx on the OPENED fd, never by path: size and mtime have to describe
  // the bytes openat2 confined, and a second resolve would not be confined.
  void on_file_stat(Completed done) {
    const uint32_t idx = done.idx;
    const uint16_t gen = done.gen;
    struct io_uring_cqe* const cqe = done.cqe;
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    const int fd = c.file_io->fd;
    c.file_io->fd = -1;
    if (!c.live || c.gen != gen) {
      arm_file_close(idx, fd, gen);
      return;
    }
    if (cqe->res < 0) {
      arm_file_close(idx, fd, gen);
      app_.file_reject(c.app);
      file_wake(idx);
      return;
    }
    size_t want = 0;
    const bool read_owed = app_.file_stat(c.app, c.file_io->stx, &want);
    if (!read_owed || want == 0) {
      arm_file_close(idx, fd, gen);
      if (read_owed) app_.file_ready_now(c.app, 0);
      file_wake(idx);
      return;
    }
    // A large file is mapped, not read: the sends walk the mapping and the
    // fd is done with. A failed mmap is not an error - the read path below
    // serves the same bytes, only slower, and `want` is a WINDOW whatever
    // the answer here was, so falling through cannot ask for the file.
    const size_t maplen = App::file_map_len(c.app);
    if (maplen != 0) {
      void* m = ::mmap(nullptr, maplen, PROT_READ, MAP_PRIVATE, fd, 0);
      if (m != MAP_FAILED) {
        arm_file_close(idx, fd, gen);
        app_.file_mapped(c.app, static_cast<const char*>(m), maplen);
        file_wake(idx);
        return;
      }
    }
    c.file_io->fd = fd;
    c.file_io->nbytes = want;
    c.file_io->filled = 0;
    c.file_io->offset = 0;
    c.file_io->stx_size = static_cast<size_t>(c.file_io->stx.stx_size);
    arm_file_read(idx);
  }

  void arm_file_read(uint32_t idx) {
    Conn& c = conns_[idx];
    char* buf = app_.file_buffer(c.app, c.file_io->nbytes);
    c.file_io->reading = true;
    struct io_uring_sqe* s = sqe();
    io_uring_prep_read(s, c.file_io->fd, buf + c.file_io->filled,
                       static_cast<unsigned>(c.file_io->nbytes - c.file_io->filled),
                       c.file_io->offset + c.file_io->filled);
    io_uring_sqe_set_data64(s, detail::tag(detail::kFileRead, c.gen, idx));
  }

  // A short read is ordinary and resumes; res == 0 before the end is the
  // file shrinking under the Content-Length statx already named, which is a
  // framing lie - refused, not sent.
  void on_file_read(Completed done) {
    const uint32_t idx = done.idx;
    const uint16_t gen = done.gen;
    struct io_uring_cqe* const cqe = done.cqe;
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    c.file_io->reading = false;
    const int fd = c.file_io->fd;
    if (!c.live || c.gen != gen) {
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
      arm_file_open(idx);
      return;
    }
    if (cqe->res < 0) {
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
      app_.file_error(c.app, std::strerror(-cqe->res));
      file_wake(idx);
      return;
    }
    c.file_io->filled += static_cast<size_t>(cqe->res);
    if (cqe->res != 0 && c.file_io->filled < c.file_io->nbytes) {
      arm_file_read(idx);
      return;
    }
    if (c.file_io->filled < c.file_io->nbytes) {
      // Short of the window with nothing left to read: the file shrank under
      // the Content-Length statx already promised. The framing would lie, so
      // the answer is refused rather than sent.
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
      app_.file_error(c.app, "the file shrank while it was read");
      file_wake(idx);
      return;
    }
    c.file_io->offset += c.file_io->filled;
    // The fd stays open while the file still owes windows; continue_conn
    // arms the next read once the round this one feeds has drained.
    if (c.file_io->offset >= c.file_io->stx_size) {
      c.file_io->fd = -1;
      arm_file_close(idx, fd, gen);
    }
    app_.file_ready_now(c.app, c.file_io->filled);
    file_wake(idx);
  }

  // SO_MEMINFO through the ring.
  void arm_meminfo(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_sock(s, SOCKET_URING_OP_GETSOCKOPT, static_cast<int>(idx), SOL_SOCKET,
                           SO_MEMINFO, c.meminfo, sizeof(c.meminfo));
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kMeminfo, c.gen, idx));
  }

  // The peer's address, through liburing's own prep - the last argument
  // is what picks the peer over this socket's own name. Only when
  // someone is logging.
  void arm_peer(uint32_t idx) {
    Conn& c = conns_[idx];
    if (c.peer == nullptr) c.peer.reset(new typename Conn::PeerAddr());
    c.peer->addrlen = sizeof(c.peer->addr);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_cmd_getsockname(s, static_cast<int>(idx),
                                  reinterpret_cast<struct sockaddr*>(&c.peer->addr),
                                  &c.peer->addrlen, 1);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kPeer, c.gen, idx));
  }
  // The peer's RAW sockaddr for the log; "-" and one line if the kernel
  // has no such cmd.
  void on_peer(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    if (WM_UNLIKELY(cqe->res < 0)) {
      static bool warned = false;
      if (!warned) {
        warned = true;
        say_server_error(app_.error_log(), std::string("peer address unavailable (") +
                                               std::strerror(-cqe->res) + "); %h logs '-'");
      }
      return;
    }
    if (c.peer != nullptr && c.peer->addrlen > 0 &&
        static_cast<size_t>(c.peer->addrlen) <= sizeof(c.peer->addr)) {
      c.app.peer = &c.peer->addr;
      c.app.peer_len = static_cast<uint8_t>(
          c.peer->addrlen > 255 ? 255 : c.peer->addrlen);
    }
  }

  // The round's byte bound, from the socket's own books.
  void on_meminfo(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    size_t cap = Conn::kRoundFloor;
    if (WM_LIKELY(cqe->res >= 0)) {
      const uint32_t used = c.meminfo[SK_MEMINFO_WMEM_QUEUED] > c.meminfo[SK_MEMINFO_WMEM_ALLOC]
                                ? c.meminfo[SK_MEMINFO_WMEM_QUEUED]
                                : c.meminfo[SK_MEMINFO_WMEM_ALLOC];
      const uint32_t buf = c.meminfo[SK_MEMINFO_SNDBUF];
      const size_t free_b = buf > used ? buf - used : 0;
      if (free_b > cap) cap = free_b;
    }
    c.round_cap = cap;
    if (c.sending) return;
    continue_conn(idx);
  }

  // RESOLVE a plan into iovecs: a sink segment carried an OFFSET, and this
  // is the first moment the address is final.
  void take_plan(Conn& c, const typename App::Plan& req) {
    // What this round needs, not what a round could ever need: allocating
    // kMsgIovMax was 1024 entries, 16 KB, on every connection that ever
    // lent - and a slow reader holds it for as long as it stalls.
    const unsigned want = req.iovlen + 1;  // + the sink head, when it prepends
    if (WM_UNLIKELY(c.msg_iov_cap < want)) {
      c.msg_iov_heap = std::make_unique<struct iovec[]>(want);
      c.msg_iov_cap = want;
    }
    struct iovec* const iov = c.iov();
    c.msg_iovlen = 0;
    c.plan_byte_total = 0;
    bool sink_covered = false;
    for (unsigned i = 0; i < req.iovlen; i++) {
      const typename App::Plan::Seg& sg = req.iov[i];
      if (sg.iov_base != nullptr) {
        iov[c.msg_iovlen].iov_base = const_cast<char*>(sg.iov_base);
      } else {
        iov[c.msg_iovlen].iov_base = c.out.data() + sg.off;
        sink_covered = true;
      }
      iov[c.msg_iovlen].iov_len = sg.iov_len;
      c.plan_byte_total += sg.iov_len;
      c.msg_iovlen++;
    }
    if (!sink_covered && !c.out.empty()) {
      for (unsigned i = c.msg_iovlen; i > 0; i--) iov[i] = iov[i - 1];
      iov[0].iov_base = c.out.data();
      iov[0].iov_len = c.out.size();
      c.plan_byte_total += c.out.size();
      c.msg_iovlen++;
    }
  }

  // The delivery continuation: a fully drained sink is the one signal every
  // protocol produces. Backlog first, then the App.
  void continue_conn(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.out.empty()) {
      arm_send(idx);
      return;
    }
    typename App::Plan req;
    req.byte_cap = c.round_cap;
    if (!app_.spell_next_round(c.app, c.out, req)) c.close_after_send = true;
    arm_file_open(idx);
    arm_compute_task(idx);
    arm_watchers(idx);
    if (req.iovlen != 0) {
      take_plan(c, req);
      arm_send(idx);
      return;
    }
    if (!c.out.empty()) {
      arm_send(idx);
      return;
    }
    // Nothing went out this round, so the window lent to the last one is
    // off the wire and the buffer is free. THIS is the only point where the
    // next window may be read - doing it on the round that just lent the
    // buffer out overwrites the bytes still being sent.
    if (c.file_io != nullptr && c.file_io->fd >= 0 && !c.file_io->reading &&
        c.file_io->offset < c.file_io->stx_size) {
      const size_t left = c.file_io->stx_size - c.file_io->offset;
      c.file_io->nbytes = left < kResponseFileWindow ? left : kResponseFileWindow;
      c.file_io->filled = 0;
      arm_file_read(idx);
      return;
    }
    if (c.close_after_send) {
      c.close_after_send = false;
      begin_close(idx);
      return;
    }
    c.idle = true;
    c.deadline_s = now_s_ + idle_timeout_;
    // Nothing owed and nothing on the wire - the one point where handing the
    // file read buffer back cannot pull it out from under anybody.
    if ((c.file_io == nullptr || !c.file_io->reading) && !app_.pending(c.app)) {
      App::file_release(c.app);
    }
  }
  // One completion, by tag.
  void handle(struct io_uring_cqe* cqe) {
    const uint64_t ud = io_uring_cqe_get_data64(cqe);
    const uint8_t kind = static_cast<uint8_t>(ud >> 56);
    const uint16_t gen = static_cast<uint16_t>(ud >> 32);
    const uint32_t idx = static_cast<uint32_t>(ud);
    // The try is HERE and not around a dispatch() of its own: a separate
    // function took on_send and its tail back out of line, and this is
    // the hottest path in the reactor - measured, 4678 bytes of fused
    // handle became 3796 of dispatch plus 2145 of on_send plus 1598 of
    // its tail, and a bench lost 5%.
    try {
      switch (kind) {
        case detail::kAccept: on_accept(idx, cqe); break;
        case detail::kRecv: on_recv(idx, gen, cqe); break;
        case detail::kSend: on_send(idx, gen, cqe); break;
        case detail::kMeminfo: on_meminfo(idx, gen, cqe); break;
        case detail::kFileOpen: on_file_open({idx, gen, cqe}); break;
        case detail::kFileStat: on_file_stat({idx, gen, cqe}); break;
        case detail::kFileRead: on_file_read({idx, gen, cqe}); break;
        case detail::kFileClose: break;
        case detail::kLog: on_log(gen, idx, cqe); break;
        case detail::kPeer: on_peer(idx, gen, cqe); break;
        case detail::kClose:
          if (WM_UNLIKELY(cqe->res == -ECANCELED)) {
            struct io_uring_sqe* s = sqe();
            io_uring_prep_close_direct(s, idx);
            io_uring_sqe_set_data64(s, detail::tag(detail::kClose, gen, idx));
          }
          break;
        case detail::kShutdown: break;
        // The first two only report: a failure in either cancels the rest of
        // the chain, and the third is where the socket is finally the
        // kernel's, so that is the one that acts.
        case detail::kTlsUlp:
          // ENOTCONN is the peer having left between the accept and this
          // option: a race no arrangement avoids and nobody's fault.
          if (WM_UNLIKELY(cqe->res < 0)) {
            if (cqe->res == -ENOTCONN) {
              begin_close(idx);
              break;
            }
            conn_failed("tls: setsockopt(TCP_ULP)", cqe->res);
          }
          break;
        case detail::kTlsTx:
          if (WM_UNLIKELY(cqe->res < 0)) conn_failed("tls: setsockopt(TLS_TX)", cqe->res);
          break;
        // The connection is already going; a peer that will not take the
        // alert is not a thing this end can do anything about.
        case detail::kTlsBye: break;
        case detail::kTlsRx: on_tls_ready({idx, gen, cqe}); break;
        case detail::kTlsTxKey: on_tls_tx_key({idx, gen, cqe}); break;
        case detail::kComputeTask:
          on_compute_task(idx, gen, detail::watch_slot(cqe->user_data), cqe);
          break;
        case detail::kWatch: on_watch(idx, gen, detail::watch_slot(cqe->user_data), cqe); break;
        case detail::kStop: stop_ = true; break;
        default: break;
      }
    } catch (const ConnFailed& f) {
      connection_failed(idx, f);
    }
  }

  // The one place a ConnFailed lands, whoever threw it.
  void connection_failed(uint32_t idx, const ConnFailed& f) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    say_connection_failed(f, conns_[idx]);
    begin_close(idx);
  }

  // One wait and one batch; bounded to a second even without a budget, so
  // the timeout clocks get a wake when nothing completes.
  bool step(const int64_t* deadline, bool bounded) {
    if (replenish_ != 0) {
      io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
      replenish_ = 0;
    }
    flush_log();
    if (bounded) {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      const int64_t left =
          *deadline - (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec);
      struct io_uring_cqe* first = nullptr;
      if (left <= 0) {
        io_uring_submit(&ring_);
      } else {
        struct __kernel_timespec ts {left / 1000000000, left % 1000000000};
        io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
      }
    } else {
      struct __kernel_timespec ts {1, 0};
      struct io_uring_cqe* first = nullptr;
      io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
    }
    {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      now_s_ = static_cast<int64_t>(now.tv_sec);
    }
    app_.on_tick();
    // #shed: how much work arrived that we have not answered yet. It is
    // a load of a u32 out of the shared ring - no syscall, and current
    // as of this instant - and it is the only number that says whether
    // this core is keeping up, because it is the queue this core is
    // behind on. Taken HERE: after the wait, before the drain, so it is
    // the depth of what this pass is about to do rather than what is
    // left over from it.
    bool worked = false;
    struct io_uring_cqe* cqe = nullptr;
    while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
      handle(cqe);
      io_uring_cqe_seen(&ring_, cqe);
      worked = true;
      if (bounded) {
        struct timespec now {};
        ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        if (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec >= *deadline) break;
      }
    }
    if (!rearm_.empty()) {
      for (uint32_t idx : rearm_) {
        Conn& c = conns_[idx];
        if (c.live && !c.close_after_send) arm_recv(idx);
      }
      rearm_.clear();
    }
    if (now_s_ != last_reap_s_) {
      last_reap_s_ = now_s_;
      const size_t nwords = live_bits_.size();
      for (size_t w = 0; w < nwords; w++) {
        // begin_close only CLEARS bits and no accept runs inside this
        // sweep, so a snapshot can go stale in one direction only - the
        // c.live guard below still catches that.
        uint64_t bits = live_bits_[w];
        while (bits != 0) {
          const uint32_t i = static_cast<uint32_t>(w * 64) + __builtin_ctzll(bits);
          bits &= bits - 1;
          Conn& c = conns_[i];
          if (!c.live) continue;
          if (!c.sending && app_.timed(c.app)) {
            c.deadline_s = now_s_ + idle_timeout_;
            continue_conn(i);
            continue;
          }
          // #30: a watcher that said nothing for as long as it allowed.
          // This is NOT the connection's own deadline - the peer on the
          // socket is fine, some other descriptor is quiet - so it is
          // asked first and it never closes anything.
          if (c.w_deadline_s != 0 && c.w_deadline_s < now_s_) {
            const int slot = App::watcher_waiting_slot(c.app);
            if (slot >= 0) {
              c.w_deadline_s = 0;
              step_watch(i, c, slot, App::watcher_deadline(c.app, slot));
            } else {
              c.w_deadline_s = 0;
            }
            continue;
          }
          if (c.deadline_s >= now_s_) continue;
          if (c.sending) {
            if (!c.close_after_send) {
              c.close_after_send = true;
              struct io_uring_sqe* s = sqe();
              io_uring_prep_shutdown(s, static_cast<int>(i), SHUT_RDWR);
              s->flags |= IOSQE_FIXED_FILE;
              io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, i));
            }
          } else if (WM_UNLIKELY(c.tls != nullptr) && !c.tls->offloaded) {
            // A TLS connection that ran out of time before the kernel
            // ever got its keys did not just go idle.
            connection_failed(i, ConnFailed{"tls: a handshake that never finished", -ETIMEDOUT});
          } else {
            begin_close(i);
          }
        }
      }
    }
    if (draining_ && !stop_) {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      const int64_t at = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
      if (live_ == 0 || at >= drain_deadline_) stop_ = true;
    }
    return worked;
  }

  App& app_;
  struct io_uring ring_ {};
  bool ring_up_ = false;
  bool stop_ = false;
  bool bundles_ = false;
  int log_fd_ = -1;
  int err_fd_ = -1;
  unsigned sq_entries_ = 0;
  // Whose exception this is, when the reactor has to give up. See fatal().
  mrb_state* mrb_ = nullptr;
  int backlog_ = SOMAXCONN;
  int header_timeout_ = 60;
  int send_timeout_ = 60;
  int idle_timeout_ = 75;
  int64_t now_s_ = 0;
  int64_t last_reap_s_ = 0;
  uint32_t max_conns_ = 0;
  uint32_t listener_base_ = 0;
  bool unix_listener_[kMaxListeners] = {};
  bool tls_handed_over_said_ = false;
  static constexpr unsigned kSaidMax = 24;
  const char* said_[kSaidMax] = {};
  unsigned said_count_ = 0;
  // Null on a listener that serves cleartext, which is also how a slot
  // knows which it is - there is no second flag to keep in step.
  ktls_keys* tls_keys_[kMaxListeners] = {};
  int bound_port_[kMaxListeners] = {};
  std::vector<std::string> unix_paths_;
  uint32_t nlisteners_ = 0;
  bool listeners_closed_ = false;
  bool draining_ = false;
  int64_t drain_deadline_ = 0;
  uint32_t live_ = 0;
  std::vector<uint64_t> live_bits_;
  char* pool_ = nullptr;
  // #80: the threads a compute task is answered by. Empty until the first run
  // stops; ComputePool::stop() runs from its own destructor.
  ComputePool compute_;
  struct io_uring_buf_ring* buf_ring_ = nullptr;
  unsigned replenish_ = 0;
  // Built in place and never moved: a slot holds a coroutine handle and
  // four raw pointers it owns, so growing an array of them is not a
  // thing this should be able to do by accident. max_conns_ is decided
  // once, from the FD budget, before the first accept.
  std::unique_ptr<Conn[]> conns_;
  std::vector<uint32_t> rearm_;
};

}  // namespace webmachine

#endif
