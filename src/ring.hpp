// The reactor: one io_uring, one thread, every connection.
//
// It lives here and not in webmachine.hpp because it is a template on
// the application type, so it has to be a header - and only four
// translation units instantiate one. The other nineteen read
// webmachine.hpp and were paying for 2159 lines they never name.
#ifndef WEBMACHINE_RING_HPP
#define WEBMACHINE_RING_HPP

#include "http1.hpp"
#include "ring_setup.hpp"

#include <sys/utsname.h>

#include <cstdio>

namespace webmachine
{

template <class App> class Ring
{
  public:
    // One reactor, one io backend, no globals.
    explicit Ring(App &application) : app_(application)
    {
    }
    Ring(const Ring &) = delete;
    Ring &operator=(const Ring &) = delete;

    // The ring exit is what ends surviving connections, and what unlinks a
    // unix listener's path.
    ~Ring()
    {
        // The workers are told through this ring, so they go first.
        compute_.stop();
        for (ktls_keys *&k : tls_keys_) {
            ktls_keys_free(k);
            k = nullptr;
        }
        if (ring_up_) {
            close_listeners();
            // Each unlink is waited for by its own completion. A count alone
            // is wrong here: the listener closes submitted just above complete
            // too, and a wait that took those for the unlinks returned before
            // the unlink ran. The ring exit then cancelled the queued unlink,
            // and the path stayed - which is what the floor bintest saw under
            // the sanitizer.
            const uint64_t unlink_tag = detail::tag(detail::kSetup, 0, detail::kStUnlink);
            unsigned count = 0;
            for (const std::string &path : unix_paths_) {
                // The name, not the socket: this server bound it, and between
                // then and now another instance may have taken it over. Only a
                // socket is unlinked, and a newer one belongs to whoever bound
                // it - a missing entry needs nothing done at all.
                struct stat st {
                };
                if (::stat(path.c_str(), &st) != 0 || !S_ISSOCK(st.st_mode))
                    continue;
                struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_);
                if (sqe == nullptr) {
                    io_uring_submit(&ring_);
                    sqe = io_uring_get_sqe(&ring_);
                    if (sqe == nullptr)
                        break;
                }
                io_uring_prep_unlink(sqe, path.c_str(), 0);
                io_uring_sqe_set_data64(sqe, unlink_tag);
                count++;
            }
            if (count != 0)
                io_uring_submit(&ring_);
            while (count != 0) {
                struct io_uring_cqe *completion = nullptr;
                if (io_uring_wait_cqe(&ring_, &completion) != 0)
                    break;
                if (io_uring_cqe_get_data64(completion) == unlink_tag)
                    count--;
                io_uring_cqe_seen(&ring_, completion);
            }
        }
        if (buf_ring_ != nullptr)
            io_uring_free_buf_ring(&ring_, buf_ring_, kBufCount, kBufGroup);
        if (pool_ != nullptr)
            ::munmap(pool_, static_cast<size_t>(kBufCount) * kBufSize);
        if (ring_up_)
            io_uring_queue_exit(&ring_);
    }

    // Everything through the ring: unlink, socket_direct, setsockopt, bind,
    // listen as one linked chain, every CQE checked, a failure naming its stage.
    void init(const RingConfig &ring_config)
    {
        mrb_ = ring_config.mrb;
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
        constexpr unsigned kSqFloor = 1024;
        constexpr unsigned kSetupFlags =
            IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
        const unsigned sq_wanted = ring_config.sq_entries != 0 ? ring_config.sq_entries : kSqWanted;
        const unsigned sq_floor = sq_wanted < kSqFloor ? sq_wanted : kSqFloor;
        struct io_uring_params p {
        };
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
        log_fd_ = ring_config.log_fd;
        err_fd_ = ring_config.err_fd;
        backlog_ = ring_config.backlog != 0 ? ring_config.backlog : SOMAXCONN;
        header_timeout_ = ring_config.header_timeout != 0 ? ring_config.header_timeout : 60;
        send_timeout_ = ring_config.send_timeout != 0 ? ring_config.send_timeout : 60;
        idle_timeout_ = ring_config.idle_timeout != 0 ? ring_config.idle_timeout : 75;
        app_.set_send_timeout(send_timeout_);
        max_conns_ = derive_max_conns({nofile});
        if (max_conns_ == 0) {
            mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                       "RLIMIT_NOFILE %i leaves no room for connections "
                       "(reserve %d + body files %d + listeners %d)",
                       static_cast<mrb_int>(nofile), static_cast<int>(kFdReserve),
                       static_cast<int>(kBodyFilesMax), static_cast<int>(kMaxListeners));
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
        void *mem =
            ::mmap(nullptr, pool_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            mrb_raisef(mrb_, E_WM_ERROR(mrb_), "mmap pool: %s", std::strerror(errno));
        }
        pool_ = static_cast<char *>(mem);

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
        buf_tail_ = kBufCount;
        bundles_ = (ring_.features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
        rewrite_entries_ = kernel_shortens_bundle_entries();

        if (ring_config.nlisteners == 0 || ring_config.nlisteners > kMaxListeners) {
            mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener count %d out of range (1..%d)",
                       static_cast<int>(ring_config.nlisteners), static_cast<int>(kMaxListeners));
        }
        for (uint32_t li = 0; li < ring_config.nlisteners; li++) {
            setup_listener(li, ring_config.listeners[li]);
            setup_keys(li, ring_config.listeners[li]);
        }
        nlisteners_ = ring_config.nlisteners;

        conns_ = std::make_unique<Conn[]>(max_conns_);
        live_bits_.assign((static_cast<size_t>(max_conns_) + 63) / 64, 0);
        rearm_.reserve(64);

        if (ring_config.stop_fd >= 0) {
            struct io_uring_sqe *sqe = setup_sqe();
            io_uring_prep_poll_add(sqe, ring_config.stop_fd, POLLIN);
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kStop, 0, 0));
        }

        for (uint32_t li = 0; li < nlisteners_; li++)
            arm_accept(li);
    }

    // Every setup step wants an SQE and none of them can go on without one.
    struct io_uring_sqe *setup_sqe()
    {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_);
        if (sqe == nullptr)
            mrb_raise(mrb_, E_WM_ERROR(mrb_), "SQ empty at setup");
        return sqe;
    }

    // Loop until the stop signal's completion lands.
    void run()
    {
        while (!stop_)
            tick(nullptr);
    }

    // One bounded step: the budget bounds the work, not just the wait, and
    // the batch is interrupted between completions.
    bool tick(const struct __kernel_timespec *budget)
    {
        if (budget == nullptr)
            return step(nullptr, false);
        struct timespec now {
        };
        ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        int64_t deadline = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
        deadline += budget->tv_sec * 1000000000 + budget->tv_nsec;
        return step(&deadline, true);
    }

    // Readable exactly when this ring has completions to hand over.
    int fd() const
    {
        return ring_up_ ? ring_.ring_fd : -1;
    }

    // Did the stop signal's completion land?
    bool stopped() const
    {
        return stop_;
    }

    // Drain, then forget: the listeners close at once, and what survives the
    // grace is ended by the destructor's ring exit.
    void drain(int64_t grace_ns)
    {
        if (draining_)
            return;
        draining_ = true;
        close_listeners();
        struct timespec now {
        };
        ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        drain_deadline_ = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec + grace_ns;
        if (live_ == 0 || grace_ns <= 0)
            stop_ = true;
    }

    // How many accepted connections are still being served.
    uint32_t live_conns() const
    {
        return live_;
    }

    // The derived capacity - what this machine actually allows.
    uint32_t max_conns() const
    {
        return max_conns_;
    }

    // A TCP listener's real port, including the kernel's pick for port 0.
    int bound_port(uint32_t listener_index) const
    {
        return listener_index < kMaxListeners ? bound_port_[listener_index] : 0;
    }

  private:
    // One listener as one linked chain; a stale unix path is unlinked outside
    // the chain, because ENOENT there is normal.
    void setup_listener(uint32_t listener_index, const ListenerSpec &want)
    {
        const uint32_t slot = listener_base_ + listener_index;
        const bool is_unix = want.unix_path != nullptr;
        struct sockaddr_un sun {
        };
        struct sockaddr_in sin {
        };
        struct sockaddr *sa = nullptr;
        socklen_t salen = 0;
        if (is_unix) {
            sun.sun_family = AF_UNIX;
            const size_t payload_length = std::strlen(want.unix_path);
            if (payload_length >= sizeof(sun.sun_path)) {
                mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener %d: unix path too long (%i)",
                           static_cast<int>(listener_index), static_cast<mrb_int>(payload_length));
            }
            std::memcpy(sun.sun_path, want.unix_path, payload_length + 1);
            sa = reinterpret_cast<struct sockaddr *>(&sun);
            salen = sizeof(sun);

            struct io_uring_sqe *sqe = setup_sqe();
            io_uring_prep_unlink(sqe, want.unix_path, 0);
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, 0, 0));
            io_uring_submit_and_wait(&ring_, 1);
            struct io_uring_cqe *completion = nullptr;
            if (io_uring_peek_cqe(&ring_, &completion) == 0) {
                if (completion->res < 0 && completion->res != -ENOENT) {
                    mrb_raisef(mrb_, E_WM_ERROR(mrb_), "unlink %s: %s", want.unix_path,
                               std::strerror(-completion->res));
                }
                io_uring_cqe_seen(&ring_, completion);
            }
        } else {
            if (want.port < 0 || want.port > 65535) {
                mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener %d: port %d out of range",
                           static_cast<int>(listener_index), want.port);
            }
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = htonl(INADDR_ANY);
            sin.sin_port = htons(static_cast<uint16_t>(want.port));
            sa = reinterpret_cast<struct sockaddr *>(&sin);
            salen = sizeof(sin);
        }

        static const int kOne = 1;
        unsigned chain = 0;
        {
            struct io_uring_sqe *sqe = setup_sqe();
            io_uring_prep_socket_direct(sqe, is_unix ? AF_UNIX : AF_INET, SOCK_STREAM, 0, slot, 0);
            sqe->flags |= IOSQE_IO_LINK;
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, 0, detail::kStSocket));
            chain++;

            if (!is_unix) {
                sqe = setup_sqe();
                io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, slot, SOL_SOCKET,
                                       SO_REUSEADDR, const_cast<int *>(&kOne), sizeof(kOne));
                sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
                io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, 0, detail::kStSockopt));
                chain++;
            }

            sqe = setup_sqe();
            io_uring_prep_bind(sqe, slot, sa, salen);
            sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, 0, detail::kStBind));
            chain++;

            sqe = setup_sqe();
            io_uring_prep_listen(sqe, slot, backlog_);
            sqe->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, 0, detail::kStListen));
            chain++;
        }
        io_uring_submit_and_wait(&ring_, chain);
        {
            // Every CQE of the chain has to be seen before anything else can
            // use this ring, so the first failure is kept and raised after the
            // drain rather than in the middle of it.
            std::string failed;
            struct io_uring_cqe *cqe = nullptr;
            while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
                if (cqe->res < 0 && failed.empty()) {
                    const uint32_t conn = static_cast<uint32_t>(io_uring_cqe_get_data64(cqe));
                    failed = cqe->res != -ECANCELED ? std::string(detail::stage_name(conn)) + ": " +
                                                          std::strerror(-cqe->res)
                                                    : std::string("setup chain canceled");
                }
                io_uring_cqe_seen(&ring_, cqe);
            }
            if (!failed.empty()) {
                mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d %s",
                           static_cast<int>(listener_index), failed.c_str());
            }
        }
        if (is_unix)
            unix_paths_.emplace_back(want.unix_path);
        unix_listener_[listener_index] = is_unix;

        if (!is_unix) {
            bound_port_[listener_index] = want.port;
            if (want.port == 0) {
                struct sockaddr_storage ss {
                };
                socklen_t slen = sizeof(ss);
                struct io_uring_sqe *sqe = setup_sqe();
                io_uring_prep_cmd_getsockname(sqe, static_cast<int>(slot),
                                              reinterpret_cast<struct sockaddr *>(&ss), &slen, 0);
                sqe->flags |= IOSQE_FIXED_FILE;
                io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, 0, detail::kStName));
                io_uring_submit_and_wait(&ring_, 1);
                struct io_uring_cqe *completion = nullptr;
                int resource = -EIO;
                if (io_uring_peek_cqe(&ring_, &completion) == 0) {
                    resource = completion->res;
                    io_uring_cqe_seen(&ring_, completion);
                }
                if (resource < 0) {
                    mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                               "listener %d: port 0 needs the bound port read back and this kernel "
                               "cannot (SOCKET_URING_OP_GETSOCKNAME: %s) - name a port",
                               static_cast<int>(listener_index), std::strerror(-resource));
                }
                if (ss.ss_family == AF_INET) {
                    bound_port_[listener_index] =
                        ntohs(reinterpret_cast<struct sockaddr_in *>(&ss)->sin_port);
                } else if (ss.ss_family == AF_INET6) {
                    bound_port_[listener_index] =
                        ntohs(reinterpret_cast<struct sockaddr_in6 *>(&ss)->sin6_port);
                } else {
                    mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d: bound name family %d?",
                               static_cast<int>(listener_index), static_cast<int>(ss.ss_family));
                }
            }
        }
    }

    // No RFC - one slot of the reactor, so what the kernel touches carries
    // the kernel's names (rule 4: the argument a field becomes) and what
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
        // Not deadline_s: the peer on this socket is fine, some other
        // descriptor is the quiet one, and nothing here closes anything.
        // #30: the earliest deadline any watcher of this connection owes.
        // Each watcher keeps its own - the App has them, one per Ruby
        // object - and this is only what the sweep has to read.
        int64_t w_deadline_s = 0;

        static constexpr size_t kRoundFloor = 64u * 1024;
        size_t round_cap = kRoundFloor;
        // The kernel writes all of these, so the landing buffer is full size
        // even though on_meminfo reads three of them. Every accept arms it,
        // so it stays inline - a pointer here would be a malloc per
        // connection to save 36 bytes.
        uint32_t meminfo[SK_MEMINFO_VARS] = {};

        // The peer's address, made only where it will be read: a logged TCP
        // connection. A unix listener, and every server started without
        // --log, carries a null pointer instead of 128 bytes.
        //
        // Kept for the slot's life once made, like FileIo below:
        // Http1::Conn::peer points into it, so reset() clears peer_len and
        // not the pointer.
        struct PeerAddr {
            socklen_t addrlen = 0;
            struct sockaddr_storage addr {
            };
        };
        std::unique_ptr<PeerAddr> peer;

        std::string out;
        std::string next;

        // response.file's one in-flight open. Lazy like everything else
        // here: most connections never open a file, and `struct statx` alone
        // is about 256 bytes.
        //
        // Made on first use and kept for the slot's life. It outlives a torn
        // down connection by one completion (see file_reading below), so
        // freeing it on close would race that completion.
        //
        // unique_ptr, not a raw pointer, for the reason iov below already is
        // one: conns_ is a vector, and a raw pointer with a destructor of its
        // own would delete the move constructor a resize needs. unique_ptr
        // keeps the move and needs no destructor.
        // No RFC - this is the kernel's ABI, so the fields carry the names of
        // the arguments they become:
        //
        //   io_uring_prep_read(sqe, fd, buf + filled, nbytes - filled,
        //                      offset + filled)
        //   io_uring_prep_statx(sqe, fd, "", AT_EMPTY_PATH, mask, &stx)
        //
        // Two of them are not arguments and say so.
        struct FileIo {
            // A plain fd, not a direct descriptor: statx is the one op here the
            // kernel takes no fixed file for. Statting the opened fd keeps size
            // and mtime describing the bytes openat2 confined; a statx by path
            // would resolve a second time, unguarded.
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
            struct statx stx {
            };
        };
        std::unique_ptr<FileIo> file_io;
        // RFC 9110 6.4: the octets of a request body that the kernel is
        // writing into a spill file right now. They live here, in the
        // reactor's own memory, and not on the connection object the
        // application holds: a stream or a connection may end while a write
        // is in flight, and the kernel writes from the memory it was given.
        std::string spill_out;
        // One spill write flies per connection. The buffer above is the one
        // the kernel is reading from, so a second write would have to swap
        // it out from under the first.
        bool spill_writing = false;

        // Not ABI: our own ceiling, one segment more than a Plan can hold, for
        // the head that rides in front of it - and the kernel's own UIO_MAXIOV.
        // It is what a round may never exceed, not what a connection carries.
        //
        // What a round actually plans, counted: an h1 answer that lends takes
        // Three segments (the head out of the sink, and a gzip member's two
        // halves out of the mapping), an h2 one nine. The ceiling is reachable
        // only by heavy multiplexing. So the common case rides inline and
        // costs no allocation at all, and the heap is for the round that does
        // not fit - see take_plan.
        //
        // Four and not sixteen: this is paid by every slot the FD budget
        // allows, live or not (conns_.resize(max_conns_)), so each entry is
        // 16 bytes times ~19k here. Four covers h1's three; h2 takes one heap
        // array on a connection that already carries an H2State.
        static constexpr unsigned kMsgIovMax = App::Plan::kSegs + 1;
        static constexpr unsigned kMsgIovInline = 4;
        size_t plan_byte_total = 0;
        struct msghdr msg {
        };

        unsigned msg_iovlen = 0;
        // How many segments the current store has room for. A high-water mark,
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
        // The close this connection owes once its file read lands. The
        // kernel is writing into the App's own buffer, and close_direct
        // would free the slot for the next accept, whose reset deletes
        // that buffer under the read.
        bool close_owed = false;
        bool idle = false;

        typename App::Conn app;

        // Where the resolved iovecs live: inline until a round needs more,
        // heap from then on. `iov()` is the one way to reach them.
        struct iovec msg_iov_inline[kMsgIovInline];
        std::unique_ptr<struct iovec[]> msg_iov_heap;
        struct iovec *iov()
        {
            return msg_iov_heap ? msg_iov_heap.get() : msg_iov_inline;
        }

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
            ktls_exchange *x = nullptr;
            // The two crypto_info blobs, copied out of the exchange. The
            // largest is ChaCha20-Poly1305: 12 iv, 32 key, 0 salt, 8 rec_seq
            // plus the 4-byte header.
            unsigned char info[2][64] = {};
            size_t info_len[2] = {};
            // recvmsg needs a msghdr that outlives the submit, and a multishot
            // one outlives many completions; the kernel reads namelen and
            // controllen out of it to size what it writes into each buffer.
            struct msghdr recv_msg {
            };
            // RFC 8446 6.1's close_notify, kept here for the same reason as
            // recv_msg: it is submitted and then waited for, so the header,
            // the control buffer and the alert itself all outlive the call
            // that spelled them.
            struct msghdr bye_msg {
            };
            struct iovec bye_iov {
            };
            unsigned char bye[2] = {1, 0}; // warning, close_notify
            unsigned char bye_control[CMSG_SPACE(1)] = {};
            // RFC 8446 4.6.3: the KeyUpdate this side sends before it turns its
            // own send key - handshake type 24, a body of one octet, and that
            // octet 0 for update_not_requested. It is submitted and then
            // waited for, so it outlives the call that spelled it, exactly as
            // the alert above does.
            struct msghdr ku_msg {
            };
            struct iovec ku_iov {
            };
            unsigned char ku[5] = {24, 0, 0, 1, 0};
            unsigned char ku_control[CMSG_SPACE(1)] = {};
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
            ~Tls()
            {
                ktls_exchange_free(x);
            }
        };
        std::unique_ptr<Tls> tls;
    };

    // The reactor cannot go on, and it is not this library's place to
    // decide what that means for the process - it is embedded, and the
    // process belongs to somebody else. So it raises, and the embedder's
    // Ruby sees Webmachine::Error and chooses. There is no second branch:
    // init() refuses a RingConfig without a VM, so this always has one.
    // A failure that belongs to one connection. It throws, the completion
    // handler below catches it, says what happened and closes that
    // connection. One peer's bad day is not the process's end; `fatal`
    // below is for when it is.
    //
    // `what` is always a string literal: the once-only reporting keys on
    // the pointer, so two calls with the same literal are the same fault.
    struct ConnFailed {
        const char *what;
        int err; // a negative errno where the kernel gave one, 0 where it did not
    };
    [[noreturn]] static void conn_failed(const char *what, int out_error = 0)
    {
        throw ConnFailed{what, out_error};
    }

    // The error log is where these belong, and with a peer to name they
    // carry it. Without a log they fall to stderr - and there once per
    // distinct reason, so a peer that can provoke one cannot provoke a
    // line per attempt.
    void say_connection_failed(const ConnFailed &field, const Conn &conn)
    {
        const std::string why = field.err < 0
                                    ? std::string(field.what) + ": " + std::strerror(-field.err)
                                    : std::string(field.what);
        Logger *element = app_.error_log();
        if (element != nullptr && element->enabled) {
            log_internal_error(
                *element, {conn.peer != nullptr
                               ? std::string_view{reinterpret_cast<const char *>(&conn.peer->addr),
                                                  static_cast<size_t>(conn.peer->addrlen)}
                               : std::string_view{},
                           {},
                           why,
                           0});
            return;
        }
        for (unsigned i = 0; i < said_count_; i++) {
            if (said_[i] == field.what)
                return;
        }
        if (said_count_ < kSaidMax)
            said_[said_count_++] = field.what;
        std::fprintf(stderr, "webmachine: %s (said once)\n", why.c_str());
    }

    [[noreturn]] void fatal(const char *what)
    {
        mrb_raise(mrb_, E_WM_ERROR(mrb_), what);
        // mruby declares mrb_raise mrb_noreturn, but that macro (common.h)
        // resolves to nothing under -std=c++20: it asks for __GNUC__ &&
        // !__STRICT_ANSI__, and a strict -std= (rather than -std=gnu=) defines
        // __STRICT_ANSI__. So the compiler cannot see what is true either way -
        // with MRB_USE_CXX_EXCEPTION the raise throws, without it it longjmps -
        // and warns that a [[noreturn]] function returns. This says it instead.
        WM_UNREACHABLE();
    }

    // The same, with the sentence built by mruby instead of by a 160-byte
    // buffer on the way to it. %d, %i, %s and %v are mrb_format's, not
    // printf's - there is no length modifier left to get wrong.
    template <typename... Args> [[noreturn]] void fatalf(const char *fmt, Args... args)
    {
        mrb_raisef(mrb_, E_WM_ERROR(mrb_), fmt, args...);
        WM_UNREACHABLE();
    }

    // Never null on return, or a raise: see sqe_or_raise.
    struct io_uring_sqe *sqe_or_submit()
    {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_);
        if (mrb_likely(sqe != nullptr))
            return sqe;
        return sqe_or_raise(mrb_, &ring_);
    }

    static constexpr uint32_t kStreamAccess = 0;
    static constexpr uint32_t kStreamError = 1;

    // Both streams, once per round, riding the submit that was happening anyway.
    void flush_log()
    {
        flush_access();
        flush_error();
    }

    // The whole batch in one send: small, constant-shaped records.
    void flush_access()
    {
        if (log_fd_ < 0)
            return;
        Logger *allow = app_.access_log();
        if (allow == nullptr || allow->in_flight || allow->pending.empty())
            return;
        allow->pending.swap(allow->flight);
        allow->in_flight = true;
        arm_access_write(allow);
    }
    // send, not write: a dead daemon must be -EPIPE in a CQE, not a SIGPIPE.
    void arm_access_write(Logger *allow)
    {
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_send(sqe, log_fd_, allow->flight.data(), allow->flight.size(), MSG_NOSIGNAL);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kLog, 0, kStreamAccess));
    }

    // One record per flush, as two linked sends.
    void flush_error()
    {
        if (err_fd_ < 0)
            return;
        Logger *element = app_.error_log();
        if (element == nullptr || element->in_flight || element->pending.size() < sizeof(ErrRec))
            return;
        ErrRec round;
        std::memcpy(&round, element->pending.data(), sizeof round);
        const size_t whole = sizeof(ErrRec) + round.dynamic_len;
        if (element->pending.size() < whole)
            return;
        element->flight.assign(element->pending, 0, whole);
        element->pending.erase(0, whole);
        element->in_flight = true;
        arm_error_write(element);
    }
    // MSG_WAITALL is what makes the link safe: IO_LINK breaks only on failure,
    // and a short send is not one.
    void arm_error_write(Logger *element)
    {
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_send(sqe, err_fd_, element->flight.data(), sizeof(ErrRec),
                           MSG_NOSIGNAL | MSG_WAITALL);
        sqe->flags |= IOSQE_IO_LINK;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kLog, 1, kStreamError));
        sqe = sqe_or_submit();
        io_uring_prep_send(sqe, err_fd_, element->flight.data() + sizeof(ErrRec),
                           element->flight.size() - sizeof(ErrRec), MSG_NOSIGNAL | MSG_WAITALL);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kLog, 0, kStreamError));
    }

    // The rule: every line formatted lands. A refused write is a named refusal.
    void on_log(uint16_t generation, uint32_t stream, struct io_uring_cqe *completion)
    {
        Logger *logger = stream == kStreamError ? app_.error_log() : app_.access_log();
        if (logger == nullptr)
            return;
        if (mrb_unlikely(completion->res < 0)) {
            if (stream == kStreamError && completion->res == -ECANCELED)
                return;
            fatalf("%s log write failed: %s - refusing to drop lines",
                   stream == kStreamError ? "error" : "access", std::strerror(-completion->res));
        }
        if (stream == kStreamError) {
            if (generation == 1)
                return;
            logger->flight.clear();
            logger->in_flight = false;
            return;
        }
        const size_t took = static_cast<size_t>(completion->res);
        if (mrb_unlikely(took < logger->flight.size())) {
            logger->flight.erase(0, took);
            arm_access_write(logger);
            return;
        }
        logger->flight.clear();
        logger->in_flight = false;
    }

    // The certificate a TLS listener answers with, and the two suites this
    // build speaks. Once per listener, at boot: every exchange this
    // listener ever opens is opened from it.
    // ktls_keys is a C handle: every refusal below unwinds past it now, so
    // its free belongs to a destructor and not to a line before each of
    // four returns.
    struct HeldKeys {
        ktls_keys *k = nullptr;
        explicit HeldKeys(ktls_keys *keys) : k(keys)
        {
        }
        ~HeldKeys()
        {
            if (k != nullptr)
                ktls_keys_free(k);
        }
        HeldKeys(const HeldKeys &) = delete;
        HeldKeys &operator=(const HeldKeys &) = delete;
        ktls_keys *release()
        {
            ktls_keys *const out = k;
            k = nullptr;
            return out;
        }
    };

    void setup_keys(uint32_t listener_index, const ListenerSpec &want)
    {
        if (want.cert_pem == nullptr)
            return;
        // The certificate before the kernel, deliberately: both can be wrong
        // at once, and the one the operator can fix is the one worth saying.
        // It also means a machine without the module still checks the config.
        HeldKeys keys{ktls_keys_server(want.cert_pem, want.cert_len, want.key_pem, want.key_len)};
        if (keys.k == nullptr) {
            mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener %d certificate: %s",
                       static_cast<int>(listener_index), ktls_last_error());
        }
        // AES first where the machine has the instructions, ChaCha first
        // otherwise (two suites, and why not three). Said out
        // loud because it decides whether a NIC can ever take the record
        // layer over, and because it is not otherwise visible from outside.
        const bool aes_is_fast = ktls_aes_is_fast();
        std::fprintf(stderr, "webmachine: listener %u offers %s first (aes instructions: %s)\n",
                     listener_index,
                     aes_is_fast ? "TLS_AES_128_GCM_SHA256" : "TLS_CHACHA20_POLY1305_SHA256",
                     aes_is_fast ? "yes" : "no");
        const char *suites = aes_is_fast ? "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
                                         : "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        if (ktls_keys_set_ciphers(keys.k, suites) != 0) {
            mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d ciphers: %s",
                       static_cast<int>(listener_index), ktls_last_error());
        }
        // Both, in preference order. Nothing downstream reads the answer:
        // RFC 9113 3.4's preface is the first thing an h2 client sends, and
        // Http1::feed_parse already decides on it - over TLS those bytes
        // arrive exactly as they do in the clear.
        static const char *const kProtocols[] = {"h2", "http/1.1"};
        if (ktls_keys_set_alpn(keys.k, kProtocols, 2) != 0) {
            mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d alpn: %s",
                       static_cast<int>(listener_index), ktls_last_error());
        }
        if (!ktls_available()) {
            const int status = ktls_load_module();
            if (status != 0 || !ktls_available()) {
                mrb_raisef(
                    mrb_, E_WM_ERROR(mrb_),
                    "listener %d serves TLS and this kernel has no tls ULP (modprobe tls): %s",
                    static_cast<int>(listener_index), ktls_last_error());
            }
        }
        tls_keys_[listener_index] = keys.release();
    }

    // The listeners leave through the ring; idempotent, or a later accept
    // would lose its slot.
    void close_listeners()
    {
        if (listeners_closed_)
            return;
        listeners_closed_ = true;
        for (uint32_t i = 0; i < nlisteners_; i++) {
            // The multishot accept holds the listening socket itself, so
            // closing the fixed-table entry left it in LISTEN and peers kept
            // arriving: a drain under any traffic at all never reached zero
            // connections, and only the ring exit ended it. The accept is
            // cancelled by its own tag first; nothing reads that completion.
            struct io_uring_sqe *sqe = sqe_or_submit();
            io_uring_prep_cancel64(sqe, detail::tag(detail::kAccept, 0, i), 0);
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kPollRemove, 0, 0));
            sqe = sqe_or_submit();
            io_uring_prep_close_direct(sqe, listener_base_ + i);
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kClose, 0, listener_base_ + i));
        }
        io_uring_submit(&ring_);
    }

    // Multishot accept_direct against the fixed listener slot.
    void arm_accept(uint32_t listener_index)
    {
        if (draining_)
            return;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_multishot_accept_direct(sqe, listener_base_ + listener_index, nullptr,
                                              nullptr, 0);
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kAccept, 0, listener_index));
    }

    // Room for the one cmsg an offloaded socket carries, TLS_GET_RECORD_TYPE.
    static constexpr size_t kTlsCmsgSpace = CMSG_SPACE(sizeof(unsigned char));

    // Multishot recv out of the buffer ring, bundles where the kernel offers
    // them - and two other shapes for a connection that is doing TLS.
    void arm_recv(uint32_t index)
    {
        Conn &c = conns_[index];
        struct io_uring_sqe *sqe = sqe_or_submit();
        if (mrb_unlikely(c.tls != nullptr)) {
            if (!c.tls->offloaded) {
                // One completion at a time while the exchange runs. The moment it
                // is done this process must stop reading: bytes it takes off the
                // socket after that are records the kernel's own record layer is
                // about to be made responsible for, and nothing here could decrypt
                // them once the exchange is freed. A multishot recv has no pause,
                // so the handshake does not use one.
                io_uring_prep_recv(sqe, static_cast<int>(index), nullptr, 0, 0);
                sqe->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
                sqe->buf_group = kBufGroup;
                io_uring_sqe_set_data64(sqe, detail::tag(detail::kRecv, c.gen, index));
                return;
            }
            // Offloaded: never a plain recv ("Never a plain recv on an
            // offloaded socket"). A record that is not application data is EIO on
            // recv and a control message on recvmsg. The kernel sizes what it
            // writes into each buffer from these two lengths, so the msghdr has to
            // outlive the submit - it lives in Tls for that reason.
            c.tls->recv_msg = msghdr{};
            c.tls->recv_msg.msg_controllen = kTlsCmsgSpace;
            io_uring_prep_recvmsg_multishot(sqe, static_cast<int>(index), &c.tls->recv_msg, 0);
            sqe->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
            sqe->buf_group = kBufGroup;
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kRecv, c.gen, index));
            return;
        }
        io_uring_prep_recv_multishot(sqe, static_cast<int>(index), nullptr, 0, 0);
        sqe->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
        sqe->buf_group = kBufGroup;
        if (bundles_)
            sqe->ioprio |= IORING_RECVSEND_BUNDLE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kRecv, c.gen, index));
    }

    // The handshake, and the only thing this connection does until it is
    // over. mruby-ktls names no descriptor: bytes in through feed, bytes
    // out through take, and the socket stays the reactor's. What comes out
    // of here is an ordinary send on the same slot.
    void tls_advance(uint32_t index)
    {
        Conn &c = conns_[index];
        ktls_step step = KTLS_READING;
        if (mrb_unlikely(ktls_exchange_step(c.tls->x, &step) != 0)) {
            conn_failed("tls: the key exchange failed");
        }
        // Unconditional and after the step, because ktls.h says a step that
        // answers KTLS_READING may still owe bytes.
        std::string &sink = c.sending ? c.next : c.out;
        for (;;) {
            char chunk[4096];
            const size_t count = ktls_exchange_take(c.tls->x, chunk, sizeof chunk);
            if (count == 0)
                break;
            sink.append(chunk, count);
        }
        if (step != KTLS_DONE) {
            // Exactly one read is armed at a time, and whoever writes last
            // arms it: a flight going out means on_send does, because two
            // reads on one connection would feed the exchange two halves of
            // the peer's next flight in whatever order they completed.
            if (c.sending || !c.out.empty()) {
                if (!c.sending)
                    arm_send(index);
                return;
            }
            arm_recv(index);
            return;
        }
        // Everything the exchange still holds is read here, in the order
        // ktls.h asks for: the backlog first, because draining it can consume
        // a post-handshake record, and the crypto_info last, because that is
        // where the record sequence is finally settled.
        c.tls->handshaking = false;
        for (;;) {
            char chunk[4096];
            const size_t count = ktls_exchange_backlog(c.tls->x, chunk, sizeof chunk);
            if (count == 0)
                break;
            c.tls->early.append(chunk, count);
        }
        for (int dir = 0; dir < 2; dir++) {
            size_t length = 0;
            const void *info =
                ktls_crypto_info(c.tls->x, static_cast<ktls_direction>(dir), &length);
            if (mrb_unlikely(info == nullptr || length > sizeof c.tls->info[dir])) {
                conn_failed("tls: the agreed keys are not a shape the kernel takes");
            }
            std::memcpy(c.tls->info[dir], info, length);
            c.tls->info_len[dir] = length;
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
            if (!c.sending)
                arm_send(index);
            return;
        }
        tls_handover(index);
    }

    // A key per direction, linked so the order is the kernel's to keep
    // rather than two completions to sort out. The ULP went on at accept.
    // The options go on the direct descriptor through the ring, like every
    // other option this reactor sets.
    void tls_handover(uint32_t index)
    {
        Conn &c = conns_[index];
        if (io_uring_sq_space_left(&ring_) < 2)
            io_uring_submit(&ring_);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(index),
                               ktls_sol_tls(), ktls_optname(KTLS_TX), c.tls->info[KTLS_TX],
                               static_cast<uint32_t>(c.tls->info_len[KTLS_TX]));
        sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kTlsTx, c.gen, index));

        sqe = sqe_or_submit();
        io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(index),
                               ktls_sol_tls(), ktls_optname(KTLS_RX), c.tls->info[KTLS_RX],
                               static_cast<uint32_t>(c.tls->info_len[KTLS_RX]));
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kTlsRx, c.gen, index));
    }

    // RFC 8446 4.6.3, answered: turn the receive secret one notch and put
    // the new crypto_info on the socket. The kernel restarts that
    // direction's sequence at zero, which is what a key change leaves,
    // and the exchange keeps the secret precisely for this - it is why
    // ktls_exchange_release exists rather than a free.
    //
    // ULP is already on, so this is one option and not a chain, and the
    // read is armed again only once the kernel has the key.
    void tls_next_receive_key(uint32_t index)
    {
        Conn &c = conns_[index];
        if (mrb_unlikely(ktls_next_key(c.tls->x, KTLS_RX) != 0)) {
            conn_failed("tls: the key update could not be answered");
        }
        size_t len = 0;
        const void *info = ktls_crypto_info(c.tls->x, KTLS_RX, &len);
        if (mrb_unlikely(info == nullptr || len > sizeof c.tls->info[KTLS_RX])) {
            begin_close(index);
            return;
        }
        std::memcpy(c.tls->info[KTLS_RX], info, len);
        c.tls->info_len[KTLS_RX] = len;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(index),
                               ktls_sol_tls(), ktls_optname(KTLS_RX), c.tls->info[KTLS_RX],
                               static_cast<uint32_t>(len));
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kTlsRx, c.gen, index));
    }

    // The last of the three. From here the socket is the kernel's record
    // layer and this connection is ordinary again - except that its recv
    // is a recvmsg, and whatever the peer pipelined behind its Finished
    // has been waiting and goes first.
    // One connection, and the slot it lives in - the reactor knows a
    // connection by both and needs both.
    struct Slot {
        uint32_t idx;
        Conn &conn;
    };

    // One completion as the reactor hands it on: the connection slot it
    // names, the generation that slot was in when the op was armed (a slot
    // that has since been reused answers a stale generation, and the
    // completion is dropped), and the CQE itself.
    struct Completed {
        uint32_t idx;
        uint16_t gen;
        struct io_uring_cqe *cqe;
    };

    void on_tls_ready(Completed done)
    {
        const uint32_t idx = done.idx;
        const uint16_t gen = done.gen;
        struct io_uring_cqe *const cqe = done.cqe;
        if (mrb_unlikely(idx >= max_conns_))
            return;
        Conn &c = conns_[idx];
        if (!c.live || c.gen != gen || c.tls == nullptr)
            return;
        if (mrb_unlikely(cqe->res < 0)) {
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
            if (!c.live)
                return;
        }
        arm_recv(idx);
    }

    // RFC 8446 5.5: a send is at least one record and at most one per
    // 16384 bytes of it, and the larger is what is charged - the count has
    // to be an over-estimate or it is not a bound.
    static void tls_charge_records(Conn &conn, size_t bytes)
    {
        if (conn.tls->tx_limit == 0)
            return;
        static constexpr size_t kRecordPlaintextMax = 16384;
        const uint64_t records =
            bytes == 0 ? 1 : (bytes + kRecordPlaintextMax - 1) / kRecordPlaintextMax;
        conn.tls->tx_records += records;
    }

    // The send key, turned before the limit rather than after it, and only
    // where no send is in flight - the kernel must not be writing under a
    // key that is being replaced. ktls_record_limit already answers half of
    // what the RFC allows, so there is room to get here.
    bool tls_turn_send_key(uint32_t index)
    {
        Conn &c = conns_[index];
        if (c.tls == nullptr || !c.tls->offloaded)
            return false;
        if (c.tls->tx_limit == 0 || c.tls->tx_records < c.tls->tx_limit)
            return false;
        if (mrb_unlikely(ktls_next_key(c.tls->x, KTLS_TX) != 0)) {
            conn_failed("tls: the send key could not be turned before its record limit");
        }
        size_t len = 0;
        const void *info = ktls_crypto_info(c.tls->x, KTLS_TX, &len);
        if (mrb_unlikely(info == nullptr || len > sizeof c.tls->info[KTLS_TX])) {
            conn_failed("tls: the turned send key is not a shape the kernel takes");
        }
        std::memcpy(c.tls->info[KTLS_TX], info, len);
        c.tls->info_len[KTLS_TX] = len;
        c.tls->tx_records = 0;
        // RFC 8446 4.6.3: the peer is told before the key changes, and the
        // message goes out under the key it replaces. Without it the kernel
        // began encrypting under a key the peer did not have, and every long
        // AES stream - a download, a websocket, an event stream - died at
        // this exact point with nothing saying why.
        //
        // A handshake record over kTLS is a sendmsg carrying the record type
        // in a control message, the shape the close_notify alert uses. The
        // setsockopt is linked behind it, so the kernel keeps the order: the
        // KeyUpdate leaves under the old key, then the new one is installed.
        const int cmsg_type = ktls_record_type_set_cmsg();
        if (mrb_likely(cmsg_type >= 0)) {
            typename Conn::Tls &text = *c.tls;
            text.ku_iov.iov_base = text.ku;
            text.ku_iov.iov_len = sizeof text.ku;
            text.ku_msg = msghdr{};
            text.ku_msg.msg_iov = &text.ku_iov;
            text.ku_msg.msg_iovlen = 1;
            text.ku_msg.msg_control = text.ku_control;
            text.ku_msg.msg_controllen = sizeof text.ku_control;
            struct cmsghdr *comma = CMSG_FIRSTHDR(&text.ku_msg);
            comma->cmsg_level = ktls_sol_tls();
            comma->cmsg_type = cmsg_type;
            comma->cmsg_len = CMSG_LEN(1);
            if (mrb_likely(ktls_record_type_encode(KTLS_RECORD_HANDSHAKE, CMSG_DATA(comma), 1) ==
                           1)) {
                text.ku_msg.msg_controllen = CMSG_SPACE(1);
                struct io_uring_sqe *keys = sqe_or_submit();
                io_uring_prep_sendmsg(keys, static_cast<int>(index), &text.ku_msg, MSG_NOSIGNAL);
                keys->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
                io_uring_sqe_set_data64(keys, detail::tag(detail::kTlsBye, c.gen, index));
            }
        }
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(index),
                               ktls_sol_tls(), ktls_optname(KTLS_TX), c.tls->info[KTLS_TX],
                               static_cast<uint32_t>(len));
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kTlsTxKey, c.gen, index));
        return true;
    }

    // The new key is on the socket; the round goes on from where it waited.
    void on_tls_tx_key(Completed done)
    {
        const uint32_t idx = done.idx;
        const uint16_t gen = done.gen;
        struct io_uring_cqe *const cqe = done.cqe;
        if (mrb_unlikely(idx >= max_conns_))
            return;
        Conn &c = conns_[idx];
        if (!c.live || c.gen != gen)
            return;
        // ECANCELED here is the KeyUpdate linked ahead of this one failing.
        // The peer never heard that the key changes, so the key may not
        // change: the connection ends rather than encrypting under a secret
        // nobody on the other side has.
        if (mrb_unlikely(cqe->res < 0))
            conn_failed("tls: setsockopt(TLS_TX) for a record limit", cqe->res);
        send_done(idx);
    }

    // What the kernel took, dropped off the front of a plan: whole segments
    // go, the first partial one is trimmed. Nothing is allocated and
    // nothing copied - the segments that stay point at the same asset
    // mappings and lent Strings they already did.
    static void plan_drop_front(Conn &conn, size_t took)
    {
        unsigned seg = 0;
        struct iovec *const out_iov = conn.iov();
        while (seg < conn.msg_iovlen && took >= out_iov[seg].iov_len) {
            took -= out_iov[seg].iov_len;
            seg++;
        }
        if (seg < conn.msg_iovlen && took != 0) {
            out_iov[seg].iov_base = static_cast<char *>(out_iov[seg].iov_base) + took;
            out_iov[seg].iov_len -= took;
        }
        const unsigned left = conn.msg_iovlen - seg;
        for (unsigned i = 0; i < left; i++)
            out_iov[i] = out_iov[seg + i];
        conn.msg_iovlen = left;
    }

    // One sendmsg for the round; MSG_MORE when the App still owes bytes.
    //
    // MSG_WAITALL where the kernel takes it: it finishes a short send
    // itself, so the round is one operation and there is no offset to
    // carry. An offloaded connection cannot have it - tls_sw_sendmsg
    // answers EOPNOTSUPP for any flag outside MSG_MORE, MSG_DONTWAIT,
    // MSG_NOSIGNAL, MSG_SPLICE_PAGES and MSG_EOR - so that one asks for no
    // retry and resumes itself, out of `out_sent` or its own iovecs.
    //
    // The lend survives either way: resource.cpp freezes and roots the
    // String and zc_release hands it back when the round drains, never
    // when one send returns.
    void arm_send(uint32_t index)
    {
        Conn &c = conns_[index];
        // One round, one deadline. A plaintext send is MSG_WAITALL and comes
        // back once, so this is the same rule both paths follow; an
        // offloaded one comes back per partial, and refreshing the deadline
        // there let a peer that opens its window one octet at a time hold
        // the round, its lent body and its slot for as long as it liked.
        c.deadline_s = now_s_ + send_timeout_;
        struct io_uring_sqe *sqe = sqe_or_submit();
        const bool resumes = c.tls != nullptr && c.tls->offloaded;
        const int flags =
            MSG_NOSIGNAL | (resumes ? 0 : MSG_WAITALL) | (app_.pending(c.app) ? MSG_MORE : 0);
        if (c.msg_iovlen == 0) {
            io_uring_prep_send(sqe, static_cast<int>(index), c.out.data() + c.out_sent,
                               c.out.size() - c.out_sent, flags);
        } else if (c.msg_iovlen == 1 && !resumes) {
            // One segment is one buffer, and a buffer does not need an iovec.
            // sendmsg makes the kernel copy an msghdr in from user space and
            // import the vector behind it - io_msg_copy_hdr, io_sendmsg_prep,
            // copy_iovec_from_user, __import_iovec - which a profile of one h1
            // run put at over 8% of everything. send carries a pointer and a
            // length and skips all of it.
            //
            // An offloaded TLS socket keeps sendmsg: send_resume re-points the
            // vector it was given, and that path is not this one to change.
            const struct iovec *const entry = c.iov();
            io_uring_prep_send(sqe, static_cast<int>(index), entry[0].iov_base, entry[0].iov_len,
                               flags);
        } else {
            c.msg = msghdr{};
            c.msg.msg_iov = c.iov();
            c.msg.msg_iovlen = c.msg_iovlen;
            io_uring_prep_sendmsg(sqe, static_cast<int>(index), &c.msg, flags);
        }
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kSend, c.gen, index));
        c.sending = true;
    }

    // One bit per slot, so the once-a-second reap can find the live ones
    // without reading a Conn to ask. The table is sized by RLIMIT_NOFILE
    // (derive_max_conns), not by the peers actually here, so walking it
    // touched a cache line per slot however few were connected.
    void live_set(uint32_t index)
    {
        live_bits_[index >> 6] |= 1ULL << (index & 63);
    }
    void live_clear(uint32_t index)
    {
        live_bits_[index >> 6] &= ~(1ULL << (index & 63));
    }

    // RFC 8446 6.1: without it a peer cannot tell a finished stream from a
    // truncated one. Nothing here builds a record - the kernel does, from
    // the type this control message names - so it is a sendmsg like any
    // other, linked ahead of the shutdown that follows it.
    //
    // Only where the socket is already the kernel's: before the handover
    // there is no key to encrypt an alert with, and a cleartext one would
    // be noise on the wire.
    void arm_close_notify(uint32_t index)
    {
        Conn &c = conns_[index];
        if (c.tls == nullptr || !c.tls->offloaded)
            return;
        const int cmsg_type = ktls_record_type_set_cmsg();
        if (mrb_unlikely(cmsg_type < 0))
            return;

        typename Conn::Tls &t = *c.tls;
        t.bye_iov.iov_base = t.bye;
        t.bye_iov.iov_len = sizeof t.bye;
        t.bye_msg = msghdr{};
        t.bye_msg.msg_iov = &t.bye_iov;
        t.bye_msg.msg_iovlen = 1;
        t.bye_msg.msg_control = t.bye_control;
        t.bye_msg.msg_controllen = sizeof t.bye_control;
        struct cmsghdr *comma = CMSG_FIRSTHDR(&t.bye_msg);
        comma->cmsg_level = ktls_sol_tls();
        comma->cmsg_type = cmsg_type;
        comma->cmsg_len = CMSG_LEN(1);
        if (mrb_unlikely(ktls_record_type_encode(KTLS_RECORD_ALERT, CMSG_DATA(comma), 1) != 1))
            return;
        t.bye_msg.msg_controllen = CMSG_SPACE(1);

        struct io_uring_sqe *sqe = sqe_or_submit();
        // MSG_DONTWAIT: the alert is a courtesy and the close behind it is
        // not. A peer that stops reading fills the send buffer, and a
        // blocking alert then waits on POLLOUT with the linked shutdown and
        // close behind it - the slot stayed in the fixed table until that
        // peer left, and enough such peers are every slot this server has.
        // An alert that cannot go answers EAGAIN, which cancels the link;
        // the close re-submits itself on ECANCELED, and close(2) on the last
        // reference sends the FIN the shutdown would have.
        io_uring_prep_sendmsg(sqe, static_cast<int>(index), &t.bye_msg,
                              MSG_NOSIGNAL | MSG_DONTWAIT);
        sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kTlsBye, c.gen, index));
    }

    // shutdown before close_direct, linked: close_direct alone leaves the
    // socket open and the peer never sees FIN.
    void begin_close(uint32_t index)
    {
        Conn &c = conns_[index];
        if (!c.live)
            return;
        if (c.sending) {
            c.close_after_send = true;
            return;
        }
        // A transfer dying under a client is exactly the event an operator
        // wants in the log, so the line is owed here too - with the bytes that
        // really went out.
        app_.file_abandon(c.app);
        // The exchange goes now - it is the biggest thing this slot holds and
        // nothing submitted points into it. The struct around it does not: a
        // handover's three setsockopts read c.tls->info and a multishot
        // recvmsg writes through c.tls->recv_msg, and either may still be with
        // the kernel. It goes when the slot is accepted into again.
        if (c.tls != nullptr) {
            ktls_exchange_free(c.tls->x);
            c.tls->x = nullptr;
        }
        c.live = false;
        live_clear(index);
        if (live_ != 0)
            live_--;
        // A read of this connection's own buffer is with the kernel. Freeing
        // the slot now lets the next accept have it, and that accept's reset
        // deletes the buffer the read is still writing into. So the close
        // waits for the read; on_file_read finishes it. A read of a regular
        // file ends, and the slot is held only that long.
        if (c.file_io != nullptr && c.file_io->reading) {
            c.close_owed = true;
            return;
        }
        finish_close(index);
    }

    // The three ops that end a slot: the TLS alert, the shutdown, and the
    // close that frees the fixed-table entry. begin_close submits them
    // unless a file read holds this connection's buffer, and on_file_read
    // submits them when that read lands.
    void finish_close(uint32_t index)
    {
        Conn &c = conns_[index];
        c.close_owed = false;
        if (io_uring_sq_space_left(&ring_) < 3)
            io_uring_submit(&ring_);
        arm_close_notify(index);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_shutdown(sqe, static_cast<int>(index), SHUT_RDWR);
        sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kShutdown, c.gen, index));
        sqe = sqe_or_submit();
        io_uring_prep_close_direct(sqe, index);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kClose, c.gen, index));
    }

    // A new peer: its slot, its clocks, and the setsockopts TCP wants.
    void on_accept(uint32_t listener_index, struct io_uring_cqe *completion)
    {
        if (!(completion->flags & IORING_CQE_F_MORE))
            arm_accept(listener_index);
        if (completion->res < 0)
            return;
        const uint32_t index = static_cast<uint32_t>(completion->res);
        if (mrb_unlikely(index >= max_conns_))
            return;
        Conn &c = conns_[index];
        c.gen++;
        c.live = true;
        live_set(index);
        live_++;
        c.sending = false;
        c.close_after_send = false;
        c.close_owed = false;
        c.idle = false;
        c.deadline_s = now_s_ + header_timeout_;
        c.listener = static_cast<uint8_t>(listener_index);
        c.out.clear();
        c.out_sent = 0;
        c.next.clear();
        c.app.reset(static_cast<uint8_t>(listener_index), !unix_listener_[listener_index]);
        if (!unix_listener_[listener_index]) {
            static const int kOne = 1;
            struct io_uring_sqe *sqe = sqe_or_submit();
            io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(index),
                                   IPPROTO_TCP, TCP_NODELAY, const_cast<int *>(&kOne),
                                   sizeof(kOne));
            sqe->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, c.gen, index));
        }
        // A listener with a certificate hands its peer an exchange before it
        // hands it anything else; arm_recv reads this to know which shape it
        // is submitting, so it is set before the first read is armed.
        c.tls.reset();
        if (mrb_unlikely(tls_keys_[listener_index] != nullptr)) {
            c.tls.reset(new typename Conn::Tls());
            c.tls->x = ktls_exchange_open(tls_keys_[listener_index], KTLS_SERVER);
            if (mrb_unlikely(c.tls->x == nullptr)) {
                begin_close(index);
                return;
            }
            // The ULP goes on here, not at the handover - the order the kernel
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
            struct io_uring_sqe *decoded = sqe_or_submit();
            io_uring_prep_cmd_sock(decoded, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(index),
                                   IPPROTO_TCP, TCP_ULP, const_cast<char *>(kUlp), sizeof kUlp);
            decoded->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data64(decoded, detail::tag(detail::kTlsUlp, c.gen, index));
        }
        arm_meminfo(index);
        if (log_fd_ >= 0 && !unix_listener_[listener_index])
            arm_peer(index);
        arm_recv(index);
    }

    // Wire bytes to the App. Kernel-supplied ids and lengths are checked
    // before use; ENOBUFS re-arms rather than hanging the connection.
    // Nothing arrived that can be parsed: a peer that left, a kernel that
    // ran out of buffers, a completion whose own numbers do not hold. None
    // of it is the path a request takes, so none of it is in one.
    void on_recv_nothing_to_parse(Slot sqe, struct io_uring_cqe *completion)
    {
        const uint32_t idx = sqe.idx;
        Conn &c = sqe.conn;
        // A completion that carries a buffer carries it even with no bytes.
        // Some kernels report one on a clean EOF, and a buffer nobody hands
        // back is a buffer this process has lost: 2048 such closes and every
        // recv answers ENOBUFS.
        give_back_buffers(completion);
        if (completion->res == -ENOBUFS) {
            rearm_.push_back({idx, c.gen});
            return;
        }
        if (completion->res < 0 && c.tls != nullptr && c.tls->offloaded) {
            conn_failed("tls: recvmsg on an offloaded socket", completion->res);
        }
        begin_close(idx);
    }

    // Bytes for a connection that has already been told to go: the buffers
    // still have to be handed back, and nothing else does.
    void on_recv_after_close(uint32_t index, size_t total)
    {
        (void)index;
        replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
    }

    // The buffers a completion consumed, whatever became of the connection.
    // Every completion takes at least one whole buffer, and a bundle takes
    // consecutive ones, so the count is the whole of it.
    void give_back_buffers(const struct io_uring_cqe *completion)
    {
        if (!(completion->flags & IORING_CQE_F_BUFFER))
            return;
        const size_t total = completion->res > 0 ? static_cast<size_t>(completion->res) : 0;
        const size_t count = total == 0 ? 1 : (total + kBufSize - 1) / kBufSize;
        replenish_ += static_cast<uint32_t>(count);
    }

    void on_recv(uint32_t index, uint16_t generation, struct io_uring_cqe *completion)
    {
        if (mrb_unlikely(index >= max_conns_))
            return;
        Conn &c = conns_[index];
        // A slot that closed, or one already reused: the bytes are nobody's,
        // and the buffers still go back, or the pool runs dry one closed
        // connection at a time.
        if (mrb_unlikely(!c.live || c.gen != generation)) {
            give_back_buffers(completion);
            return;
        }

        if (mrb_unlikely(completion->res <= 0)) {
            on_recv_nothing_to_parse({index, c}, completion);
            return;
        }
        if (mrb_unlikely(!(completion->flags & IORING_CQE_F_BUFFER))) {
            begin_close(index);
            return;
        }
        const uint32_t bid0 = completion->flags >> IORING_CQE_BUFFER_SHIFT;
        const size_t total = static_cast<size_t>(completion->res);
        if (mrb_unlikely(bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize)) {
            begin_close(index);
            return;
        }
        if (mrb_unlikely(c.close_after_send)) {
            on_recv_after_close(index, total);
            return;
        }
        if (mrb_unlikely(c.tls != nullptr)) {
            on_recv_tls(index, {bid0, total, completion->flags});
            return;
        }
        // A tunnel owes no next request head, so header_timeout_ is not its
        // clock: what it waits for is the peer, and that is the idle one. The
        // octets that just arrived are the proof the peer is there.
        const bool tunneled = app_.tunneled(c.app);
        if (mrb_unlikely(c.idle || tunneled)) {
            c.idle = false;
            c.deadline_s = now_s_ + (tunneled ? idle_timeout_ : header_timeout_);
        }

        std::string &sink = c.sending ? c.next : c.out;
        bool closing = false;
        size_t left = total;
        uint32_t bid = bid0;
        typename App::Plan req;
        req.byte_cap = c.round_cap;
        while (left > 0) {
            const size_t count = left < kBufSize ? left : kBufSize;
            size_t offset = 0;
            if (mrb_unlikely(__builtin_mul_overflow(static_cast<size_t>(bid),
                                                    static_cast<size_t>(kBufSize), &offset))) {
                begin_close(index);
                return;
            }
            const bool last = left <= kBufSize;
            typename App::Plan *plan = (last && !c.sending) ? &req : nullptr;
            if (!closing)
                closing = !app_.connection_feed(c.app, {pool_ + offset, count}, {sink, plan});
            // The peer stopped reading and keeps sending. Multishot recv
            // delivers while a send is in flight, so a websocket handler's
            // answers pile up in `next` for as long as the send timeout
            // allows - unbounded, and the client decides the rate.
            if (mrb_unlikely(!closing && sink.size() > kTunnelOutCap))
                closing = true;
            left -= count;
            bid = (bid + 1) & (kBufCount - 1);
            replenish_++;
        }

        if (!c.sending) {
            if (req.iovlen != 0) {
                take_plan(c, req);
                arm_send(index);
            } else if (!c.out.empty()) {
                arm_send(index);
            }
        }
        // A run that named a file answered nothing yet: the open is the
        // reactor's, and its result reaches the wire through continue_conn.
        arm_file_open(index);
        arm_spill_write(index);
        arm_compute_task(index);
        arm_watchers(index);
        // Unless the name never reached the kernel at all - a refusal this
        // process spelled itself owes no completion, so nothing else would
        // ever come back to collect it.
        if (mrb_unlikely(App::file_answerable(c.app) || App::run_resumable(c.app)) && !c.sending) {
            continue_conn(index);
        }
        if (mrb_unlikely(closing)) {
            round_closed(index, c);
            if (!c.live)
                return;
        }
        if (mrb_unlikely(!(completion->flags & IORING_CQE_F_MORE)))
            rearm_.push_back({index, c.gen});
    }

    // The App will take nothing more on this connection.
    void round_closed(uint32_t index, Conn &conn)
    {
        if (conn.tls != nullptr && conn.tls->offloaded) {
            conn_failed("tls: the parser refused what the kernel decrypted", -EPROTO);
        }
        if (conn.sending)
            conn.close_after_send = true;
        else
            begin_close(index);
    }

    // What a round owes once the App has seen its bytes: the answer on the
    // wire, an open the run deferred, and the close it may have asked for.
    // Shared, because bytes reach the App from three places - the buffer
    // ring, an offloaded socket's recvmsg, and the backlog a handshake left.
    void finish_round(uint32_t index, typename App::Plan &request, bool closing)
    {
        Conn &c = conns_[index];
        if (!c.sending) {
            if (request.iovlen != 0) {
                take_plan(c, request);
                arm_send(index);
            } else if (!c.out.empty()) {
                arm_send(index);
            }
        }
        // A run that named a file answered nothing yet: the open is the
        // reactor's, and its result reaches the wire through continue_conn.
        arm_file_open(index);
        arm_compute_task(index);
        // Unless the name never reached the kernel at all - a refusal this
        // process spelled itself owes no completion, so nothing else would ever
        // come back to collect it.
        if (mrb_unlikely(App::file_answerable(c.app)) && !c.sending)
            continue_conn(index);
        if (mrb_unlikely(closing))
            round_closed(index, c);
    }

    // One contiguous stretch of plaintext to the App, and the round it
    // finishes. `last` is what lets a Plan form, so a caller that has the
    // whole of what arrived says so.
    void deliver(uint32_t index, const char *data, size_t length, bool last)
    {
        Conn &c = conns_[index];
        // The same clock the cleartext path keeps: plaintext arrived, so the
        // peer is there, and a tunnel waits on the idle time rather than on a
        // head that never comes.
        const bool tunneled = app_.tunneled(c.app);
        if (mrb_unlikely(c.idle || tunneled)) {
            c.idle = false;
            c.deadline_s = now_s_ + (tunneled ? idle_timeout_ : header_timeout_);
        }
        typename App::Plan req;
        req.byte_cap = c.round_cap;
        typename App::Plan *plan = (last && !c.sending) ? &req : nullptr;
        std::string &sink = c.sending ? c.next : c.out;
        const bool closing = !app_.connection_feed(c.app, {data, length}, {sink, plan});
        finish_round(index, req, closing);
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

    void on_recv_tls(uint32_t index, RecvBytes read_bytes)
    {
        const uint32_t bid0 = read_bytes.bid0;
        const size_t total = read_bytes.total;
        const uint32_t flags = read_bytes.flags;
        Conn &c = conns_[index];
        const size_t offset = static_cast<size_t>(bid0) * kBufSize;
        replenish_++;

        if (c.tls->handshaking) {
            if (mrb_unlikely(total > kBufSize ||
                             ktls_exchange_feed(c.tls->x, pool_ + offset, total) != 0)) {
                conn_failed("tls: the peer's handshake bytes were refused");
            }
            tls_advance(index);
            return;
        }

        // Between the handshake finishing and the last of the three
        // setsockopts landing, nothing is armed and nothing may arrive - so a
        // completion here belongs to a socket that is already the kernel's.
        struct io_uring_recvmsg_out *o =
            io_uring_recvmsg_validate(pool_ + offset, static_cast<int>(total), &c.tls->recv_msg);
        if (mrb_unlikely(o == nullptr)) {
            conn_failed("tls: a recvmsg header that does not fit its own buffer");
        }
        // A record whose plaintext did not fit, or a control message that did
        // not. Either would hand the parser a piece of something and call it
        // the whole thing, so neither is read.
        if (mrb_unlikely((o->flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)) {
            conn_failed("tls: a record too large for one buffer");
        }
        // An alert or a post-handshake record reaches a plain recv as EIO and
        // nothing else; here it says which it is ("Never a plain
        // recv on an offloaded socket").
        ktls_record record = KTLS_RECORD_UNKNOWN;
        for (struct cmsghdr *cm = io_uring_recvmsg_cmsg_firsthdr(o, &c.tls->recv_msg);
             cm != nullptr; cm = io_uring_recvmsg_cmsg_nexthdr(o, &c.tls->recv_msg, cm)) {
            if (cm->cmsg_level == ktls_sol_tls() && cm->cmsg_type == ktls_record_type_cmsg()) {
                record = ktls_record_type(CMSG_DATA(cm), cm->cmsg_len - CMSG_LEN(0));
            }
        }
        if (mrb_unlikely(record != KTLS_RECORD_DATA)) {
            // An alert ends the connection because that is what one is for -
            // close_notify included, which is the ordinary way a peer leaves.
            if (record != KTLS_RECORD_HANDSHAKE) {
                if (record == KTLS_RECORD_ALERT) {
                    begin_close(index);
                    return;
                }
                conn_failed("tls: a record of no known type");
            }
            tls_next_receive_key(index);
            return;
        }
        const void *payload = io_uring_recvmsg_payload(o, &c.tls->recv_msg);
        const size_t len =
            io_uring_recvmsg_payload_length(o, static_cast<int>(total), &c.tls->recv_msg);
        if (len != 0) {
            deliver(index, static_cast<const char *>(payload), len, true);
            if (!c.live)
                return;
        }
        if (!(flags & IORING_CQE_F_MORE))
            rearm_.push_back({index, c.gen});
    }

    // What the kernel took, and what is still owed.
    void on_send(uint32_t index, uint16_t generation, struct io_uring_cqe *completion)
    {
        if (mrb_unlikely(index >= max_conns_))
            return;
        Conn &c = conns_[index];
        if (c.gen != generation)
            return;
        c.sending = false;
        // The connection ended while this send was with the kernel. That it
        // is over is all this completion still means: the close is already
        // on its way, and nothing may spell a round on a slot going back.
        if (mrb_unlikely(!c.live))
            return;

        if (mrb_unlikely(completion->res < 0)) {
            send_refused(index, c, completion->res);
            return;
        }
        // MSG_WAITALL means the kernel already retried; fewer bytes than offered
        // is a dead peer, and a half-written response cannot be resumed - HTTP/1
        // has no restart point and an h2 frame cut in half breaks the whole
        // connection's framing. So the only answer is to drop it.
        const size_t took = static_cast<size_t>(completion->res);
        const size_t offered = c.msg_iovlen != 0 ? c.plan_byte_total : c.out.size() - c.out_sent;
        if (mrb_unlikely(took != offered)) {
            // Nobody retried this one, so what is left is still owed and the
            // stream carries on where it stopped. That is the one thing a
            // half-written response can do; what it cannot do is start again.
            if (mrb_unlikely(c.tls != nullptr) && c.tls->offloaded) {
                send_resume(index, c, took);
                return;
            }
            begin_close(index);
            return;
        }
        c.deadline_s = now_s_ + send_timeout_;
        if (mrb_unlikely(c.tls != nullptr) && c.tls->offloaded)
            tls_charge_records(c, took);
        c.out.clear();
        c.out_sent = 0;
        c.msg_iovlen = 0;
        c.plan_byte_total = 0;
        // A send key at its record limit is turned here, where nothing is in
        // flight; what the round owes next waits for that completion. The
        // null test is at this side of the call so a cleartext send does not
        // make one.
        if (mrb_unlikely(c.tls != nullptr) && tls_turn_send_key(index))
            return;
        send_done(index);
    }

    // A send the kernel refused outright.
    void send_refused(uint32_t index, Conn &conn, int out_error)
    {
        if (conn.tls != nullptr && conn.tls->offloaded) {
            conn_failed("tls: send on an offloaded socket", out_error);
        }
        begin_close(index);
    }

    // Only an offloaded connection gets here: without MSG_WAITALL nobody
    // retried, so what is left is still owed and the stream carries on
    // where it stopped. That is the one thing a half-written response can
    // do; what it cannot do is start again.
    void send_resume(uint32_t index, Conn &conn, size_t took)
    {
        if (conn.msg_iovlen != 0) {
            plan_drop_front(conn, took);
            conn.plan_byte_total -= took;
        } else {
            conn.out_sent += took;
        }
        tls_charge_records(conn, took);
        arm_send(index);
    }

    // What a finished send leaves owed: the rest of the round, the next
    // one, or the connection going idle. Inline in on_send, which is the
    // path every response takes; on_tls_tx_key calls it because a rekey
    // happens once per 2^23 records and may pay for the call.
    void send_done(uint32_t index)
    {
        Conn &c = conns_[index];
        // The handshake's own bytes, now on the wire as themselves. Only once
        // nothing is left may the kernel be given the write key.
        if (mrb_unlikely(c.tls != nullptr) && !c.tls->offloaded) {
            if (c.next.empty()) {
                if (c.tls->handshaking)
                    arm_recv(index);
                else
                    tls_handover(index);
                return;
            }
            c.out.swap(c.next);
            arm_send(index);
            return;
        }
        if (!c.next.empty()) {
            c.out.swap(c.next);
            arm_send(index);
            return;
        }
        if (app_.pending(c.app)) {
            arm_meminfo(index);
            return;
        }
        continue_conn(index);
    }

    // response.file, stage 1: openat2 against the docroot fd. RESOLVE_BENEATH
    // anchors the walk to that fd, so the confinement is the kernel's and not
    // this code's - no path math here, on purpose.
    void arm_file_open(uint32_t index)
    {
        Conn &c = conns_[index];
        // The same shape as arm_compute_task: the answer is no on every
        // round that does not name a file, and file_take is a call into
        // another translation unit to hear it.
        if (mrb_likely(!App::file_waiting(c.app)))
            return;
        if (c.file_io != nullptr && c.file_io->reading)
            return; // its buffer is still under a live read
        const char *path = app_.file_take(c.app);
        if (path == nullptr)
            return;
        if (c.file_io == nullptr)
            c.file_io.reset(new Conn::FileIo());
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_openat2(sqe, docroot_fd(), path,
                              const_cast<struct open_how *>(docroot_how()));
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kFileOpen, c.gen, index));
    }

    // #80: the work a stopped run left, handed to a worker. Started here
    // and not at setup: a server whose resources never stop must not carry
    // threads it will never use, and this runs once for the whole process
    // the first time anything stops.
    // #30: what a stopped run left to wait on. The connection filed each
    // watcher under a slot; this puts a poll on its descriptor with the
    // events it asks for, and the slot rides in the tag.
    //
    // One-shot, not multishot. A watcher changes what it waits for in the
    // middle of a wait - libpq wants writable while it flushes and
    // readable while it reads, and hiredis says so through addWrite and
    // delWrite - and a one-shot poll is re-armed with the new mask
    // anyway. A multishot would have to be cancelled for every change.
    void arm_watchers(uint32_t index)
    {
        Conn &c = conns_[index];
        int slot = -1;
        while (App::watch_take(c.app, &slot))
            arm_watch(index, c, slot);
    }

    void arm_watch(uint32_t index, Conn &conn, int slot)
    {
        const int descriptor = App::watcher_descriptor(conn.app, slot);
        const unsigned mask = App::watcher_mask(conn.app, slot);
        if (descriptor < 0 || mask == 0)
            return;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_poll_add(sqe, descriptor, mask);
        const uint64_t text = detail::watch_tag(conn.gen, index, static_cast<uint8_t>(slot));
        io_uring_sqe_set_data64(sqe, text);
        App::watcher_is_armed(conn.app, slot, &ring_, text);
        // How long this one may stay quiet. The sweep reads whole seconds,
        // so a fraction becomes the next whole second up - a deadline that
        // fires early is a promise broken, one that fires late is not.
        const double quiet = App::watcher_quiet_seconds(conn.app, slot);
        if (quiet > 0.0) {
            const int64_t secs = static_cast<int64_t>(quiet) +
                                 (quiet > static_cast<double>(static_cast<int64_t>(quiet)) ? 1 : 0);
            App::watcher_armed_at(conn.app, slot, now_s_ + (secs > 0 ? secs : 1));
        }
        conn.w_deadline_s = App::watchers_soonest_deadline(conn.app);
    }

    // One readiness for one watcher. The block decides what happens next.
    void on_watch(uint32_t index, uint16_t generation, uint8_t slot,
                  struct io_uring_cqe *completion)
    {
        if (mrb_unlikely(index >= max_conns_))
            return;
        Conn &c = conns_[index];
        if (!c.live || c.gen != generation)
            return;
        // A poll this side removed, at a deadline: not a readiness, and the
        // slot may hold a new watcher by now.
        if (completion->res == -ECANCELED)
            return;
        App::watcher_is_unarmed(c.app, slot);
        // A poll that failed says the descriptor is gone. The block hears
        // nothing more; the run reads nil and answers for it.
        const unsigned revents = completion->res > 0 ? static_cast<unsigned>(completion->res)
                                                     : static_cast<unsigned>(POLLERR);
        step_watch(index, c, static_cast<int>(slot), App::watcher_event(c.app, slot, revents));
    }

    void step_watch(uint32_t index, Conn &conn, int slot, typename App::WatchStep step)
    {
        switch (step) {
            case App::WatchStep::kWait:
            case App::WatchStep::kRearm:
                // Both arm again - the mask is read fresh either way, so the two
                // differ only in what the reader learns from the name.
                arm_watch(index, conn, slot);
                return;
            case App::WatchStep::kDone:
                App::watchers_drop_slot(conn.app, slot);
                conn.w_deadline_s = App::watchers_soonest_deadline(conn.app);
                if (!conn.sending)
                    continue_conn(index);
                return;
        }
    }

    void arm_compute_task(uint32_t index)
    {
        Conn &c = conns_[index];
        // Almost every round asks and almost none has a job. Ask first, and
        // build nothing until the answer is yes.
        if (mrb_likely(!App::compute_task_waiting(c.app)))
            return;
        if (compute_.workers() == 0) {
            // One per core the process may use, less the reactor's own. Every
            // worker opens an mrb_state of its own, and nothing counts those
            // any more: the VM ceiling belonged to mruby-task, which this
            // tree no longer builds.
            const long cores = ::sysconf(_SC_NPROCESSORS_ONLN);
            const unsigned by_core = cores > 1 ? static_cast<unsigned>(cores - 1) : 1;
            const unsigned want = by_core;
            if (const char *why = compute_.start(want, kComputeDepth, &ring_)) {
                conn_failed(why, -EAGAIN);
            } else {
                compute_ts_.resize(static_cast<size_t>(want) * kComputeDepth);
            }
        }
        // #30: a value round hands over several jobs at one stop, and they
        // go to the pool together. The tag carries which stopped run and
        // which job of it, so each answer finds its own place - a
        // connection can hold several stopped runs, one per h2 stream.
        int park = -1;
        while (App::park_take_pending(c.app, &park)) {
            for (int slot = 0; slot < App::Conn::kJobSlots; slot++) {
                std::string arg;
                unsigned code = 0;
                double deadline = 0.0;
                if (!App::compute_task_take(c.app, park, slot, &code, arg, &deadline))
                    continue;
                if (!compute_.submit(
                        mrb_, code, arg, App::compute_task_user(c.app, park, slot), deadline,
                        detail::compute_task_tag(c.gen, index, static_cast<uint8_t>(park),
                                                 static_cast<uint8_t>(slot),
                                                 App::park_generation(c.app, park)))) {
                    // Every slot taken. Not a refusal this layer invents - the run
                    // is told, and it answers 503 the way it would answer anything
                    // else.
                    App::compute_task_refused(c.app, park);
                    if (!c.sending)
                        continue_conn(index);
                    return;
                }
            }
        }
    }

    // #80: what bounds a compute job now that no scheduler does. The
    // reactor owns the clock, so it arms one timeout per job and calls
    // mrb_vm_interrupt on that worker's VM when it fires. A job with no
    // max_runtime is unbounded by the author's own choice and gets no
    // timeout at all.
    //
    // Nothing cancels the timeout when the answer comes first: the pool
    // moves the job number on, and a timeout that names the job before it
    // interrupts nothing. One SQE is cheaper than a cancel plus its own
    // completion.
    // A worker began a job. Its deadline is execution time, so the timer
    // is armed here and not when the job was queued.
    void on_compute_started(uint32_t slot, uint16_t generation)
    {
        const double deadline = compute_.started(slot, generation);
        if (deadline > 0.0)
            arm_compute_deadline(slot, generation, deadline);
    }

    void arm_compute_deadline(unsigned slot, uint16_t generation, double deadline)
    {
        if (deadline <= 0.0 || compute_ts_.empty())
            return;
        // The kernel reads the timespec when the SQE is submitted, and a
        // round arms several before one submit. So each arm gets its own,
        // out of a table as large as the pool has jobs in flight - which is
        // the same bound the pool's slots carry.
        __kernel_timespec &ts = compute_ts_[compute_ts_at_];
        compute_ts_at_ = (compute_ts_at_ + 1) % compute_ts_.size();
        const int64_t whole = static_cast<int64_t>(deadline);
        ts.tv_sec = whole;
        ts.tv_nsec = static_cast<long long>((deadline - static_cast<double>(whole)) * 1e9);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_timeout(sqe, &ts, 0, 0);
        io_uring_sqe_set_data64(sqe, detail::compute_deadline_tag(slot, generation));
    }

    // The fd leaves through the ring like every other descriptor here.
    void arm_file_close(uint32_t index, int descriptor, uint16_t generation)
    {
        if (descriptor < 0)
            return;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_close(sqe, descriptor);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kFileClose, generation, index));
    }

    // The head is spelled; `spell_next_round` is what puts it on the wire, so a connection
    // mid-send is left to on_send's own continuation.
    void file_wake(uint32_t index)
    {
        if (!conns_[index].sending)
            continue_conn(index);
    }

    // RFC 9110 6.4: one write of a request body into its spill file. The
    // reactor asks on every recv and every round, and the answer is no
    // for every connection that is not taking a large upload.
    //
    // A blocking write(2) on this thread is what this replaces. One write
    // flies per connection: the file has one offset, and the answer
    // carries a connection and a generation with no field for a second
    // body.
    void arm_spill_write(uint32_t index)
    {
        Conn &c = conns_[index];
        if (c.spill_writing)
            return;
        BodySpill *const spelling = App::spill_waiting(c.app);
        if (mrb_likely(spelling == nullptr))
            return;
        spelling->fly_into(c.spill_out);
        c.spill_writing = true;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_write(sqe, spelling->fd, c.spill_out.data(),
                            static_cast<unsigned>(c.spill_out.size()), spelling->offset);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kSpillWrite, c.gen, index));
    }

    // The write landed, or it failed. The application counts the octets,
    // and a run that stopped for this body learns whether it may go on.
    void on_spill_write(Completed done)
    {
        const uint32_t idx = done.idx;
        if (mrb_unlikely(idx >= max_conns_))
            return;
        Conn &c = conns_[idx];
        // A connection that died under the write: the octets were written
        // from this reactor's buffer, so there is nothing to hand back.
        c.spill_writing = false;
        if (!c.live || c.gen != done.gen) {
            // The write belonged to a tenant that is gone. The slot may hold a
            // new one whose own octets queued while spill_writing still stood
            // for the old, and nothing else would arm that write until the
            // next recv - a body complete on the wire waiting on the clock.
            c.spill_out.clear();
            arm_spill_write(idx);
            if (c.live && !c.sending)
                continue_conn(idx);
            return;
        }
        app_.spill_wrote(c.app, done.cqe->res, c.spill_out);
        c.spill_out.clear();
        arm_spill_write(idx);
        if (!c.sending)
            continue_conn(idx);
    }

    // #80: a worker answered. The tag is the connection's, so the same
    // generation guard every other op relies on discards an answer whose
    // connection is already gone - the run died with the slot, and its
    // frame with it.
    //
    // Nothing is resumed here. The run needs a sink and a plan to write
    // its answer into, and this is not a point where either exists; `spell_next_round`
    // is. So this only says the answer arrived, and takes the same door
    // response.file takes.
    void on_compute_task(uint32_t word, uint16_t generation, uint8_t both,
                         struct io_uring_cqe *completion)
    {
        (void)completion;
        const uint8_t park_gen = static_cast<uint8_t>(word >> 24);
        const uint32_t idx = word & 0xffffffu;
        if (mrb_unlikely(idx >= max_conns_))
            return;
        Conn &c = conns_[idx];
        const uint8_t park = static_cast<uint8_t>(both >> 4);
        const uint8_t slot = static_cast<uint8_t>(both & 0x0f);
        const uint64_t poll_tag = detail::compute_task_tag(generation, idx, park, slot, park_gen);
        ComputeAnswer answered;
        const bool have = compute_.take(poll_tag, &answered);
        if (!have)
            answered.raised = true;
        // A raise inside a worker is the one failure nobody else can see:
        // it happened on another thread, in another VM, and the client only
        // gets a 500. So it goes to the error log whole - class, message,
        // backtrace and which worker - and it goes there even when the
        // connection is gone, because the fault is the application's either
        // way.
        if (answered.raised && have) {
            fault_report(app_.error_log(), mrb_,
                         {answered.exception, answered.step, answered.worker_name,
                          c.live && c.gen == generation && c.peer != nullptr
                              ? std::string_view{reinterpret_cast<const char *>(&c.peer->addr),
                                                 static_cast<size_t>(c.peer->addrlen)}
                              : std::string_view{},
                          static_cast<uint16_t>(answered.over_deadline ? 500 : 503)});
        }
        // A generation that moved means the connection is gone and its run
        // died with it. The answer is still taken, because the slot is the
        // pool's and would otherwise stay busy for the life of the process.
        if (!c.live || c.gen != generation)
            return;
        // The slot was taken again since this job was sent: the answer is a
        // round's that ended, and the round parked there now is not its.
        if (App::park_generation(c.app, park) != park_gen)
            return;
        App::compute_task_answered(c.app, static_cast<int>(park), static_cast<int>(slot), answered);
        if (!c.sending)
            continue_conn(idx);
    }

    // ENOENT, EXDEV (RESOLVE_BENEATH), ELOOP (RESOLVE_NO_SYMLINKS), EACCES -
    // One answer for all of them, so probing for a symlink or a traversal
    // cannot be told apart from asking for a name that was never there.
    void on_file_open(Completed done)
    {
        const uint32_t idx = done.idx;
        const uint16_t gen = done.gen;
        struct io_uring_cqe *const cqe = done.cqe;
        if (mrb_unlikely(idx >= max_conns_))
            return;
        Conn &c = conns_[idx];
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
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_statx(sqe, c.file_io->fd, "", AT_EMPTY_PATH,
                            STATX_TYPE | STATX_SIZE | STATX_MTIME, &c.file_io->stx);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kFileStat, c.gen, idx));
    }

    // statx on the opened fd, never by path: size and mtime have to describe
    // the bytes openat2 confined, and a second resolve would not be confined.
    void on_file_stat(Completed done)
    {
        const uint32_t idx = done.idx;
        const uint16_t gen = done.gen;
        struct io_uring_cqe *const cqe = done.cqe;
        if (mrb_unlikely(idx >= max_conns_))
            return;
        Conn &c = conns_[idx];
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
            if (read_owed)
                app_.file_ready_now(c.app, 0);
            file_wake(idx);
            return;
        }
        // A large file is mapped, not read: the sends walk the mapping and the
        // fd is done with. A failed mmap is not an error - the read path below
        // serves the same bytes, only slower, and `want` is a window whatever
        // the answer here was, so falling through cannot ask for the file.
        const size_t maplen = App::file_map_len(c.app);
        if (maplen != 0) {
            void *method = ::mmap(nullptr, maplen, PROT_READ, MAP_PRIVATE, fd, 0);
            if (method != MAP_FAILED) {
                arm_file_close(idx, fd, gen);
                app_.file_mapped(c.app, static_cast<const char *>(method), maplen);
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

    void arm_file_read(uint32_t index)
    {
        Conn &c = conns_[index];
        char *chunk = app_.file_buffer(c.app, c.file_io->nbytes);
        c.file_io->reading = true;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_read(sqe, c.file_io->fd, chunk + c.file_io->filled,
                           static_cast<unsigned>(c.file_io->nbytes - c.file_io->filled),
                           c.file_io->offset + c.file_io->filled);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kFileRead, c.gen, index));
    }

    // A short read is ordinary and resumes; res == 0 before the end is the
    // file shrinking under the Content-Length statx already named, which is a
    // framing lie - refused, not sent.
    void on_file_read(Completed done)
    {
        const uint32_t idx = done.idx;
        const uint16_t gen = done.gen;
        struct io_uring_cqe *const cqe = done.cqe;
        if (mrb_unlikely(idx >= max_conns_))
            return;
        Conn &c = conns_[idx];
        c.file_io->reading = false;
        const int fd = c.file_io->fd;
        if (!c.live || c.gen != gen) {
            c.file_io->fd = -1;
            arm_file_close(idx, fd, gen);
            // The connection ended under this read and its close waited for
            // it. Nothing writes that buffer now, so the slot may go back.
            if (c.close_owed && c.gen == gen) {
                finish_close(idx);
                return;
            }
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
    void arm_meminfo(uint32_t index)
    {
        Conn &c = conns_[index];
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_GETSOCKOPT, static_cast<int>(index), SOL_SOCKET,
                               SO_MEMINFO, c.meminfo, sizeof(c.meminfo));
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kMeminfo, c.gen, index));
    }

    // The peer's address, through liburing's own prep - the last argument
    // is what picks the peer over this socket's own name. Only when
    // someone is logging.
    void arm_peer(uint32_t index)
    {
        Conn &c = conns_[index];
        if (c.peer == nullptr)
            c.peer.reset(new typename Conn::PeerAddr());
        c.peer->addrlen = sizeof(c.peer->addr);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_getsockname(sqe, static_cast<int>(index),
                                      reinterpret_cast<struct sockaddr *>(&c.peer->addr),
                                      &c.peer->addrlen, 1);
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kPeer, c.gen, index));
    }
    // The peer's raw sockaddr for the log; "-" and one line if the kernel
    // has no such cmd.
    void on_peer(uint32_t index, uint16_t generation, struct io_uring_cqe *completion)
    {
        if (mrb_unlikely(index >= max_conns_))
            return;
        Conn &c = conns_[index];
        if (c.gen != generation)
            return;
        if (mrb_unlikely(completion->res < 0)) {
            static bool warned = false;
            if (!warned) {
                warned = true;
                say_server_error(app_.error_log(), std::string("peer address unavailable (") +
                                                       std::strerror(-completion->res) +
                                                       "); %h logs '-'");
            }
            return;
        }
        if (c.peer != nullptr && c.peer->addrlen > 0 &&
            static_cast<size_t>(c.peer->addrlen) <= sizeof(c.peer->addr)) {
            c.app.peer = &c.peer->addr;
            c.app.peer_len = static_cast<uint8_t>(c.peer->addrlen > 255 ? 255 : c.peer->addrlen);
        }
    }

    // The round's byte bound, from the socket's own books.
    void on_meminfo(uint32_t index, uint16_t generation, struct io_uring_cqe *completion)
    {
        if (mrb_unlikely(index >= max_conns_))
            return;
        Conn &c = conns_[index];
        if (c.gen != generation)
            return;
        // The generation alone is not enough here. A send completes, this is
        // armed, and a recv error in the same batch closes the connection -
        // same slot, same generation, and the round below would be spelled
        // onto a socket whose close is already submitted.
        if (mrb_unlikely(!c.live))
            return;
        size_t cap = Conn::kRoundFloor;
        if (mrb_likely(completion->res >= 0)) {
            const uint32_t used =
                c.meminfo[SK_MEMINFO_WMEM_QUEUED] > c.meminfo[SK_MEMINFO_WMEM_ALLOC]
                    ? c.meminfo[SK_MEMINFO_WMEM_QUEUED]
                    : c.meminfo[SK_MEMINFO_WMEM_ALLOC];
            const uint32_t chunk = c.meminfo[SK_MEMINFO_SNDBUF];
            const size_t free_b = chunk > used ? chunk - used : 0;
            if (free_b > cap)
                cap = free_b;
        }
        c.round_cap = cap;
        if (c.sending)
            return;
        continue_conn(index);
    }

    // Resolve a plan into iovecs: a sink segment carried an offset, and this
    // is the first moment the address is final.
    void take_plan(Conn &conn, const typename App::Plan &request)
    {
        // What this round needs, not what a round could ever need: allocating
        // kMsgIovMax was 1024 entries, 16 KB, on every connection that ever
        // lent - and a slow reader holds it for as long as it stalls.
        const unsigned want = request.iovlen + 1; // + the sink head, when it prepends
        if (mrb_unlikely(conn.msg_iov_cap < want)) {
            conn.msg_iov_heap = std::make_unique<struct iovec[]>(want);
            conn.msg_iov_cap = want;
        }
        struct iovec *const out_iov = conn.iov();
        conn.msg_iovlen = 0;
        conn.plan_byte_total = 0;
        bool sink_covered = false;
        for (unsigned i = 0; i < request.iovlen; i++) {
            const typename App::Plan::Seg &segment = request.iov[i];
            if (segment.iov_base != nullptr) {
                out_iov[conn.msg_iovlen].iov_base = const_cast<char *>(segment.iov_base);
            } else {
                out_iov[conn.msg_iovlen].iov_base = conn.out.data() + segment.off;
                sink_covered = true;
            }
            out_iov[conn.msg_iovlen].iov_len = segment.iov_len;
            conn.plan_byte_total += segment.iov_len;
            conn.msg_iovlen++;
        }
        if (!sink_covered && !conn.out.empty()) {
            for (unsigned i = conn.msg_iovlen; i > 0; i--)
                out_iov[i] = out_iov[i - 1];
            out_iov[0].iov_base = conn.out.data();
            out_iov[0].iov_len = conn.out.size();
            conn.plan_byte_total += conn.out.size();
            conn.msg_iovlen++;
        }
    }

    // The delivery continuation: a fully drained sink is the one signal every
    // protocol produces. Backlog first, then the App.
    void continue_conn(uint32_t index)
    {
        Conn &c = conns_[index];
        if (!c.out.empty()) {
            arm_send(index);
            return;
        }
        typename App::Plan req;
        req.byte_cap = c.round_cap;
        if (!app_.spell_next_round(c.app, c.out, req))
            c.close_after_send = true;
        arm_file_open(index);
        arm_spill_write(index);
        arm_compute_task(index);
        arm_watchers(index);
        if (req.iovlen != 0) {
            take_plan(c, req);
            arm_send(index);
            return;
        }
        if (!c.out.empty()) {
            arm_send(index);
            return;
        }
        // Nothing went out this round, so the window lent to the last one is
        // off the wire and the buffer is free. This is the only point where the
        // next window may be read - doing it on the round that just lent the
        // buffer out overwrites the bytes still being sent.
        if (c.file_io != nullptr && c.file_io->fd >= 0 && !c.file_io->reading &&
            c.file_io->offset < c.file_io->stx_size) {
            const size_t left = c.file_io->stx_size - c.file_io->offset;
            c.file_io->nbytes = left < kResponseFileWindow ? left : kResponseFileWindow;
            c.file_io->filled = 0;
            arm_file_read(index);
            return;
        }
        if (c.close_after_send) {
            c.close_after_send = false;
            begin_close(index);
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
    void handle(struct io_uring_cqe *completion)
    {
        const uint64_t user_data = io_uring_cqe_get_data64(completion);
        const uint8_t kind = static_cast<uint8_t>(user_data >> 56);
        const uint16_t generation = static_cast<uint16_t>(user_data >> 32);
        const uint32_t index = static_cast<uint32_t>(user_data);
        // The try is here and not around a dispatch() of its own. This is
        // the hottest path in the reactor, and a separate function takes
        // on_send back out of line: measured, that cost 5%.
        try {
            switch (kind) {
                case detail::kAccept:
                    on_accept(index, completion);
                    break;
                case detail::kRecv:
                    on_recv(index, generation, completion);
                    break;
                case detail::kSend:
                    on_send(index, generation, completion);
                    break;
                case detail::kMeminfo:
                    on_meminfo(index, generation, completion);
                    break;
                case detail::kFileOpen:
                    on_file_open({index, generation, completion});
                    break;
                case detail::kFileStat:
                    on_file_stat({index, generation, completion});
                    break;
                case detail::kFileRead:
                    on_file_read({index, generation, completion});
                    break;
                case detail::kFileClose:
                    break;
                case detail::kSpillWrite:
                    on_spill_write({index, generation, completion});
                    break;
                case detail::kLog:
                    on_log(generation, index, completion);
                    break;
                case detail::kPeer:
                    on_peer(index, generation, completion);
                    break;
                case detail::kClose:
                    if (mrb_unlikely(completion->res == -ECANCELED)) {
                        struct io_uring_sqe *sqe = sqe_or_submit();
                        io_uring_prep_close_direct(sqe, index);
                        io_uring_sqe_set_data64(sqe,
                                                detail::tag(detail::kClose, generation, index));
                    }
                    break;
                case detail::kShutdown:
                    break;
                case detail::kPollRemove:
                    break;
                // The first two only report: a failure in either cancels the rest of
                // the chain, and the third is where the socket is finally the
                // kernel's, so that is the one that acts.
                case detail::kTlsUlp:
                    // ENOTCONN is the peer having left between the accept and this
                    // option: a race no arrangement avoids and nobody's fault.
                    if (mrb_unlikely(completion->res < 0)) {
                        if (completion->res == -ENOTCONN) {
                            begin_close(index);
                            break;
                        }
                        conn_failed("tls: setsockopt(TCP_ULP)", completion->res);
                    }
                    break;
                case detail::kTlsTx:
                    if (mrb_unlikely(completion->res < 0))
                        conn_failed("tls: setsockopt(TLS_TX)", completion->res);
                    break;
                // The connection is already going; a peer that will not take the
                // alert is not a thing this end can do anything about.
                case detail::kTlsBye:
                    break;
                case detail::kTlsRx:
                    on_tls_ready({index, generation, completion});
                    break;
                case detail::kTlsTxKey:
                    on_tls_tx_key({index, generation, completion});
                    break;
                case detail::kComputeTask:
                    on_compute_task(index, generation, detail::watch_slot(completion->user_data),
                                    completion);
                    break;
                // #80: a job that ran past its max_runtime. The timeout also
                // completes when it is cancelled or when the job answered
                // first; the pool reads the job number and leaves such a worker
                // alone.
                case detail::kComputeDeadline:
                    if (completion->res == -ETIME)
                        compute_.interrupt(index, generation);
                    break;
                case detail::kComputeStarted:
                    on_compute_started(index, generation);
                    break;
                case detail::kWatch:
                    on_watch(index, generation, detail::watch_slot(completion->user_data),
                             completion);
                    break;
                case detail::kStop:
                    stop_ = true;
                    break;
                default:
                    break;
            }
        } catch (const ConnFailed &field) {
            // kComputeTask puts the park generation in the top byte of the
            // connection word, so its low word is not an index on its own -
            // begin_close saw a number above max_conns_ and returned, leaving
            // the connection open with nothing said. Every other kind's word
            // is the index itself.
            connection_failed(kind == detail::kComputeTask ? (index & 0xffffffu) : index, field);
        }
    }

    // The one place a ConnFailed lands, whoever threw it.
    void connection_failed(uint32_t index, const ConnFailed &field)
    {
        if (mrb_unlikely(index >= max_conns_))
            return;
        say_connection_failed(field, conns_[index]);
        begin_close(index);
    }

    // One wait and one batch; bounded to a second even without a budget, so
    // the timeout clocks get a wake when nothing completes.
    bool step(const int64_t *deadline, bool bounded)
    {
        if (replenish_ != 0) {
            if (rewrite_entries_) {
                give_back_to_ring();
            } else {
                io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
                buf_tail_ += replenish_;
                replenish_ = 0;
            }
        }
        flush_log();
        if (bounded) {
            struct timespec now {
            };
            ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
            const int64_t left =
                *deadline - (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec);
            struct io_uring_cqe *first = nullptr;
            if (left <= 0) {
                io_uring_submit(&ring_);
            } else {
                struct __kernel_timespec ts {
                    left / 1000000000, left % 1000000000
                };
                io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
            }
        } else {
            struct __kernel_timespec ts {
                1, 0
            };
            struct io_uring_cqe *first = nullptr;
            io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
        }
        {
            struct timespec now {
            };
            ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
            now_s_ = static_cast<int64_t>(now.tv_sec);
        }
        app_.clock_tick();
        // #shed: how much work arrived that we have not answered yet. One
        // load of a u32 out of the shared ring - no syscall, current as of
        // this instant - and the only number that says whether this core is
        // keeping up.
        //
        // Taken after the wait and before the drain, so it is the depth of
        // what this pass is about to do.
        bool worked = false;
        struct io_uring_cqe *cqe = nullptr;
        while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
            handle(cqe);
            io_uring_cqe_seen(&ring_, cqe);
            worked = true;
            if (bounded) {
                struct timespec now {
                };
                ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
                if (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec >= *deadline)
                    break;
            }
        }
        if (!rearm_.empty()) {
            for (const Rearm &r : rearm_) {
                Conn &conn = conns_[r.idx];
                if (conn.live && conn.gen == r.gen && !conn.close_after_send)
                    arm_recv(r.idx);
            }
            rearm_.clear();
        }
        if (now_s_ != last_reap_s_) {
            last_reap_s_ = now_s_;
            const size_t nwords = live_bits_.size();
            for (size_t window = 0; window < nwords; window++) {
                // begin_close only clears bits and no accept runs inside this
                // sweep, so a snapshot can go stale in one direction only - the
                // c.live guard below still catches that.
                uint64_t bits = live_bits_[window];
                while (bits != 0) {
                    const uint32_t i = static_cast<uint32_t>(window * 64) + __builtin_ctzll(bits);
                    bits &= bits - 1;
                    Conn &conn = conns_[i];
                    if (!conn.live)
                        continue;
                    if (!conn.sending && app_.timed(conn.app)) {
                        conn.deadline_s = now_s_ + idle_timeout_;
                        continue_conn(i);
                        continue;
                    }
                    // #30: a watcher that said nothing for as long as it allowed.
                    // This is not the connection's own deadline - the peer on the
                    // socket is fine, some other descriptor is quiet - so it is
                    // asked first and it never closes anything.
                    if (conn.w_deadline_s != 0 && conn.w_deadline_s < now_s_) {
                        // Every watcher that stayed quiet for as long as it allowed,
                        // not only the first one.
                        int over[16];
                        const size_t count =
                            App::watchers_over_deadline(conn.app, now_s_, over, 16);
                        for (size_t k = 0; k < count; k++) {
                            // The poll armed for it is still in the ring. It goes
                            // first, by its tag, so a new arming is the only one and
                            // a dropped slot leaves no poll to fire on its successor.
                            const uint64_t armed = App::watcher_poll_tag(conn.app, over[k]);
                            if (armed != 0) {
                                struct io_uring_sqe *sqe = sqe_or_submit();
                                io_uring_prep_poll_remove(sqe, armed);
                                io_uring_sqe_set_data64(
                                    sqe, detail::tag(detail::kPollRemove, conn.gen, i));
                                App::watcher_is_unarmed(conn.app, over[k]);
                            }
                            step_watch(i, conn, over[k], App::watcher_deadline(conn.app, over[k]));
                        }
                        conn.w_deadline_s = App::watchers_soonest_deadline(conn.app);
                        continue;
                    }
                    if (conn.deadline_s >= now_s_)
                        continue;
                    if (conn.sending) {
                        if (!conn.close_after_send) {
                            conn.close_after_send = true;
                            struct io_uring_sqe *sqe = sqe_or_submit();
                            io_uring_prep_shutdown(sqe, static_cast<int>(i), SHUT_RDWR);
                            sqe->flags |= IOSQE_FIXED_FILE;
                            io_uring_sqe_set_data64(sqe, detail::tag(detail::kSetup, conn.gen, i));
                        }
                    } else if (mrb_unlikely(conn.tls != nullptr) && !conn.tls->offloaded) {
                        // A TLS connection that ran out of time before the kernel
                        // ever got its keys did not just go idle.
                        connection_failed(
                            i, ConnFailed{"tls: a handshake that never finished", -ETIMEDOUT});
                    } else if (app_.going_away(conn.app, conn.out)) {
                        // RFC 6455 7.1.1: a WebSocket hears a Close frame before the
                        // socket goes. The send carries it and closes behind it.
                        conn.close_after_send = true;
                        arm_send(i);
                    } else {
                        begin_close(i);
                    }
                }
            }
        }
        if (draining_ && !stop_) {
            struct timespec now {
            };
            ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
            const int64_t index = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
            if (live_ == 0 || index >= drain_deadline_)
                stop_ = true;
        }
        return worked;
    }

    App &app_;
    struct io_uring ring_ {
    };
    bool ring_up_ = false;
    bool stop_ = false;
    int log_fd_ = -1;
    int err_fd_ = -1;
    unsigned sq_entries_ = 0;
    // Whose exception this is, when the reactor has to give up. See fatal().
    mrb_state *mrb_ = nullptr;
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
    const char *said_[kSaidMax] = {};
    unsigned said_count_ = 0;
    // Null on a listener that serves cleartext, which is also how a slot
    // knows which it is - there is no second flag to keep in step.
    ktls_keys *tls_keys_[kMaxListeners] = {};
    int bound_port_[kMaxListeners] = {};
    std::vector<std::string> unix_paths_;
    uint32_t nlisteners_ = 0;
    bool listeners_closed_ = false;
    bool draining_ = false;
    int64_t drain_deadline_ = 0;
    uint32_t live_ = 0;
    std::vector<uint64_t> live_bits_;
    // One timespec per job in flight, for the deadline SQEs above.
    std::vector<__kernel_timespec> compute_ts_;
    size_t compute_ts_at_ = 0;
    char *pool_ = nullptr;
    // #80: the threads a compute task is answered by. Empty until the first run
    // stops; ComputePool::stop() runs from its own destructor.
    ComputePool compute_;
    struct io_uring_buf_ring *buf_ring_ = nullptr;
    unsigned replenish_ = 0;
    // Where the next returned buffer goes. Entry i of the ring holds buffer
    // i, always, so a bundle's buffers are the consecutive ids after the
    // first one the completion names.
    uint32_t buf_tail_ = 0;
    bool bundles_ = false;
    bool rewrite_entries_ = false;

    // A kernel before 7.1 shortens the length of a bundle's last entry to
    // the bytes it had available, and leaves it short when that transfer
    // fails (io_uring/kbuf: don't truncate end buffer for bundles). On such
    // a kernel a returned buffer goes back as a whole entry; on 7.1 and
    // later the tail advances over the old entries, which the kernel then
    // never changed.
    static bool kernel_shortens_bundle_entries()
    {
        struct utsname u {
        };
        if (::uname(&u) != 0)
            return true;
        unsigned major = 0;
        unsigned minor = 0;
        if (std::sscanf(u.release, "%u.%u", &major, &minor) != 2)
            return true;
        return major < 7 || (major == 7 && minor < 1);
    }

    // The buffers the last batch consumed go back as whole entries. An
    // entry written here is whole again, and the buffer it names is the one
    // at its position.
    void give_back_to_ring()
    {
        const int mask = io_uring_buf_ring_mask(kBufCount);
        for (unsigned k = 0; k < replenish_; k++) {
            const uint32_t offset = (buf_tail_ + k) & static_cast<uint32_t>(mask);
            io_uring_buf_ring_add(buf_ring_, pool_ + static_cast<size_t>(offset) * kBufSize,
                                  kBufSize, static_cast<uint16_t>(offset), mask,
                                  static_cast<int>(k));
        }
        io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
        buf_tail_ += replenish_;
        replenish_ = 0;
    }
    // Built in place and never moved: a slot holds a coroutine handle and
    // four raw pointers it owns, so growing an array of them is not a
    // thing this should be able to do by accident. max_conns_ is decided
    // once, from the FD budget, before the first accept.
    std::unique_ptr<Conn[]> conns_;
    // Which connection owes a fresh recv, and which tenant of the slot
    // owed it. The generation is half the entry: sqe() submits mid-batch
    // when the queue fills, so a close and a new accept for one slot can
    // both be handled inside a single batch, and a second multishot recv
    // on one socket delivers its bytes outside the parser's order.
    struct Rearm {
        uint32_t idx;
        uint16_t gen;
    };
    std::vector<Rearm> rearm_;
};

} // namespace webmachine

#endif
