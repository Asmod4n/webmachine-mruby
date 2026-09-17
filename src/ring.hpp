// Ring is a template on the application type, so it lives in a header.
#ifndef WEBMACHINE_RING_HPP
#define WEBMACHINE_RING_HPP

#include "http1.hpp"
#include "ring_setup.hpp"

#include <sys/utsname.h>

#include <cstdio>
#include <deque>

namespace webmachine
{

template <class App> class Ring
{
  public:
    explicit Ring(App &application) : app_(application)
    {
    }
    Ring(const Ring &) = delete;
    Ring &operator=(const Ring &) = delete;

    ~Ring()
    {
        // The workers are told through this ring, so they go first.
        compute_.stop();
        if (ring_up_) {
            close_listeners();
            // Each unlink is waited for by its own completion. The listener
            // closes complete too, so a count alone takes those for the unlinks.
            const uint64_t unlink_tag = arm(op_unlink_, nullptr, detail::kSetup, detail::kStUnlink);
            unsigned count = 0;
            for (const std::string &path : unix_paths_) {
                // Another instance may have taken the name since this server
                // bound it, so only a socket is unlinked.
                struct stat st {
                };
                if (::stat(path.c_str(), &st) != 0) {
                    if (errno != ENOENT) {
                        std::fprintf(stderr, "webmachine: stat %s: %s\n", path.c_str(),
                                     std::strerror(errno));
                    }
                    continue;
                }
                if (!S_ISSOCK(st.st_mode))
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
        if (pool_ != nullptr &&
            ::munmap(pool_, static_cast<size_t>(kBufCount) * kBufSize) != 0) {
            die_errno("munmap the buffer pool", errno);
        }
        if (ring_up_) {
            io_uring_queue_exit(&ring_);
            ring_up_ = false;
        }
        // The ring is gone, so the kernel names none of these. They are
        // freed here and nowhere else.
        while (live_head_ != nullptr)
            conn_free(live_head_);
    }

    void init(const RingConfig &ring_config)
    {
        mrb_ = ring_config.mrb;
        // There is no VM to raise into. A null mrb is a bug in this tree,
        // so the process dies and says so.
        if (mrb_ == nullptr) {
            std::fputs("webmachine: RingConfig::mrb is required - the reactor raises rather than "
                       "ending a process it does not own\n",
                       stderr);
            std::abort();
        }
        int rc = 0;
        const uint64_t memlock = raise_memlock(mrb_);
        constexpr unsigned kSqFloor = 1024;
        constexpr unsigned kSetupFlags =
            IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
        const unsigned sq_wanted = ring_config.sq_entries != 0
                                       ? ring_config.sq_entries
                                       : derive_sq_entries(memlock, ring_config.rings_in_process);
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
                mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                           "io_uring_queue_init(%d): %s. RLIMIT_MEMLOCK is %i and %d ring(s) "
                           "share three quarters of it",
                           static_cast<int>(sq_entries_), std::strerror(-rc),
                           static_cast<mrb_int>(memlock),
                           static_cast<int>(ring_config.rings_in_process));
            }
        }
        // A kernel without register_ring_fd answers -EINVAL, and that is
        // no reason not to start.
        rc = io_uring_register_ring_fd(&ring_);
        if (rc < 0 && rc != -EINVAL) {
            mrb_raisef(mrb_, E_WM_ERROR(mrb_), "register_ring_fd: %s", std::strerror(-rc));
        }
        ring_up_ = true;

        const uint64_t nofile = raise_nofile(mrb_);
        log_fd_ = ring_config.log_fd;
        err_fd_ = ring_config.err_fd;
        backlog_ = ring_config.backlog != 0 ? ring_config.backlog : SOMAXCONN;
        header_timeout_ = ring_config.header_timeout != 0 ? ring_config.header_timeout : 60;
        send_timeout_ = ring_config.send_timeout != 0 ? ring_config.send_timeout : 60;
        idle_timeout_ = ring_config.idle_timeout != 0 ? ring_config.idle_timeout : 75;
        app_.set_send_timeout(send_timeout_);
        // The kernel picks the table entry for every accept, so nothing
        // here indexes by it.
        table_size_ = derive_max_conns({nofile});
        if (table_size_ == 0) {
            mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                       "RLIMIT_NOFILE %i leaves no room for connections "
                       "(reserve %d + body files %d + listeners %d)",
                       static_cast<mrb_int>(nofile), static_cast<int>(kFdReserve),
                       static_cast<int>(kBodyFilesMax), static_cast<int>(kMaxListeners));
        }
        listener_base_ = table_size_;

        rc = io_uring_register_files_sparse(&ring_, table_size_ + kMaxListeners);
        if (rc != 0) {
            mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                       "register_files_sparse(%d): %s. RLIMIT_NOFILE is %i, and that limit is "
                       "the user's rather than this process's",
                       static_cast<int>(table_size_ + kMaxListeners), std::strerror(-rc),
                       static_cast<mrb_int>(nofile));
        }
        rc = io_uring_register_file_alloc_range(&ring_, 0, table_size_);
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
            mrb_raisef(mrb_, E_WM_ERROR(mrb_),
                       "setup_buf_ring(%d): %s. This ring asked for %d submission entries and a "
                       "table of %d slots; RLIMIT_MEMLOCK is %i and %d ring(s) share three "
                       "quarters of it",
                       static_cast<int>(kBufCount), std::strerror(-bre),
                       static_cast<int>(sq_entries_), static_cast<int>(table_size_ + kMaxListeners),
                       static_cast<mrb_int>(memlock),
                       static_cast<int>(ring_config.rings_in_process));
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

        worker_ring_fds_ = ring_config.worker_ring_fds;
        nworkers_ = ring_config.nworkers;
        if (ring_config.takes_no_listener) {
            if (ring_config.nlisteners != 0) {
                mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_),
                           "a ring that answers what an acceptor sends it takes no listener, "
                           "and %d were named",
                           static_cast<int>(ring_config.nlisteners));
            }
        } else if (ring_config.nlisteners == 0 || ring_config.nlisteners > kMaxListeners) {
            mrb_raisef(mrb_, E_WM_CONFIG_ERROR(mrb_), "listener count %d out of range (1..%d)",
                       static_cast<int>(ring_config.nlisteners), static_cast<int>(kMaxListeners));
        }
        for (uint32_t li = 0; li < ring_config.nlisteners; li++) {
            setup_listener(li, ring_config.listeners[li]);
        }
        nlisteners_ = ring_config.nlisteners;

        rearm_.reserve(64);

        if (ring_config.stop_fd >= 0) {
            struct io_uring_sqe *sqe = setup_sqe();
            io_uring_prep_poll_add(sqe, ring_config.stop_fd, POLLIN);
            io_uring_sqe_set_data64(sqe, arm(op_stop_, nullptr, detail::kStop));
        }

        for (uint32_t li = 0; li < nlisteners_; li++)
            arm_accept(li);
    }

    struct io_uring_sqe *setup_sqe()
    {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_);
        if (sqe == nullptr)
            mrb_raise(mrb_, E_WM_ERROR(mrb_), "SQ empty at setup");
        return sqe;
    }

    // A worker ring has no stop signal of its own. The signalfd is the
    // acceptor's, and this passes the word.
    void stop_the_workers()
    {
        for (uint32_t w = 0; w < nworkers_; w++) {
            struct io_uring_sqe *sqe = sqe_or_submit();
            io_uring_prep_msg_ring(sqe, worker_ring_fds_[w], 0, detail::kAdoptStop, 0);
            io_uring_sqe_set_data64(sqe, 0);
        }
        if (nworkers_ != 0)
            io_uring_submit(&ring_);
    }

    void run()
    {
        while (!stop_)
            tick(nullptr);
    }

    bool tick(const struct __kernel_timespec *budget)
    {
        if (budget == nullptr)
            return step(nullptr, false);
        struct timespec now {
        };
        if (::clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
            die_errno("clock_gettime(CLOCK_MONOTONIC_COARSE)", errno);
        int64_t deadline = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
        deadline += budget->tv_sec * 1000000000 + budget->tv_nsec;
        return step(&deadline, true);
    }

    int fd() const
    {
        return ring_up_ ? ring_.ring_fd : -1;
    }

    bool stopped() const
    {
        return stop_;
    }

    void drain(int64_t grace_ns)
    {
        if (draining_)
            return;
        draining_ = true;
        close_listeners();
        struct timespec now {
        };
        if (::clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
            die_errno("clock_gettime(CLOCK_MONOTONIC_COARSE)", errno);
        drain_deadline_ = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec + grace_ns;
        if (live_ == 0 || grace_ns <= 0)
            stop_ = true;
    }

    uint32_t live_conns() const
    {
        return live_;
    }

    uint32_t max_conns() const
    {
        return table_size_;
    }

    int bound_port(uint32_t listener_index) const
    {
        return listener_index < kMaxListeners ? bound_port_[listener_index] : 0;
    }

  private:
    // The stale unix path is unlinked outside the chain: ENOENT there is
    // normal and would break a link.
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
            io_uring_sqe_set_data64(
                sqe, arm(op_setup_[listener_index][detail::kStUnlink], nullptr, detail::kSetup,
                         detail::kStUnlink));
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
            io_uring_sqe_set_data64(sqe, arm(op_setup_[listener_index][detail::kStSocket], nullptr,
                                             detail::kSetup, detail::kStSocket));
            chain++;

            if (!is_unix) {
                sqe = setup_sqe();
                io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, slot, SOL_SOCKET,
                                       SO_REUSEADDR, const_cast<int *>(&kOne), sizeof(kOne));
                sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
                io_uring_sqe_set_data64(sqe, arm(op_setup_[listener_index][detail::kStSockopt], nullptr,
                                                 detail::kSetup, detail::kStSockopt));
                chain++;
            }

            sqe = setup_sqe();
            io_uring_prep_bind(sqe, slot, sa, salen);
            sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
            io_uring_sqe_set_data64(sqe, arm(op_setup_[listener_index][detail::kStBind], nullptr,
                                             detail::kSetup, detail::kStBind));
            chain++;

            sqe = setup_sqe();
            io_uring_prep_listen(sqe, slot, backlog_);
            sqe->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data64(sqe, arm(op_setup_[listener_index][detail::kStListen], nullptr,
                                             detail::kSetup, detail::kStListen));
            chain++;
        }
        io_uring_submit_and_wait(&ring_, chain);
        {
            // Every CQE of the chain has to be seen before this ring is used
            // again, so the first failure is raised after the drain.
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
                io_uring_sqe_set_data64(sqe, arm(op_setup_[listener_index][detail::kStName], nullptr,
                                                 detail::kSetup, detail::kStName));
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

    // Members are ordered by alignment, not by topic: flags between the
    // 8-byte members cost 21 bytes of padding.
    struct Conn;

    // Its address is the SQE's user_data. An address belongs to one object
    // for as long as that object exists, so nothing is packed or numbered.
    struct Op {
        Conn *conn = nullptr;
        uint32_t aux = 0;
        uint8_t kind = 0;
    };

    struct Conn {
        // The kernel picks the direct descriptor: multishot_accept_direct
        // hands the entry back in cqe->res.
        uint32_t fd = 0;
        // What the kernel and the workers still hold. The block is freed
        // when this reaches zero and the connection is dead, and never before.
        uint32_t armed = 0;
        // Set once the peer is gone. The block stands until `armed` is zero.
        bool dead = false;
        Conn *live_prev = nullptr;
        Conn *live_next = nullptr;
        // A deque and not a vector: the SQE carries the record's address, and
        // a deque never moves an element when it grows at the back.
        // Behind a pointer: a deque allocates when it is made, and three
        // inline cost 240 bytes per peer that nearly never uses them.
        struct Slow {
            std::deque<Op> watch;
            std::deque<Op> compute;
            std::deque<Op> compute_started;
        };
        std::unique_ptr<Slow> slow;
        Slow &slow_records()
        {
            if (slow == nullptr)
                slow.reset(new Slow());
            return *slow;
        }
        int64_t deadline_s = 0;
        // The earliest deadline any watcher of this connection owes. Not
        // deadline_s: the peer on this socket is fine.
        int64_t w_deadline_s = 0;

        // One per operation that can fly beside another. Placed below the
        // fields a round reads: arming and releasing touch one of these only.
        Op op_recv;
        Op op_send;
        Op op_setup;
        Op op_meminfo;
        Op op_peer;
        Op op_shutdown;
        Op op_close;
        // Its own record, because the close of this connection may be in flight.
        Op op_poll_remove;
        Op op_file_open;
        Op op_file_stat;
        Op op_file_read;
        Op op_file_close;
        Op op_spill_write;

        static constexpr size_t kRoundFloor = 64u * 1024;
        size_t round_cap = kRoundFloor;
        // The kernel writes all of these. Inline, because a pointer would
        // cost a malloc per connection to save 36 bytes.
        uint32_t meminfo[SK_MEMINFO_VARS] = {};

        // Made only for a logged TCP connection; the rest carry a null
        // pointer instead of 128 bytes. Http1::Conn::peer points into it,
        // so it is kept once made.
        struct PeerAddr {
            socklen_t addrlen = 0;
            struct sockaddr_storage addr {
            };
        };
        std::unique_ptr<PeerAddr> peer;

        std::string out;
        std::string next;

        // Lazy: most connections never open a file, and `struct statx` alone
        // is about 256 bytes. Kept once made: it outlives a torn down
        // connection by one completion, so freeing it on close would race.
        struct FileIo {
            // A plain fd: the kernel takes no fixed file for statx. The opened
            // fd is statted so size and mtime describe the bytes openat2 confined.
            int fd = -1;
            size_t filled = 0;
            size_t nbytes = 0;
            size_t offset = 0;
            size_t stx_size = 0;
            // The App owns the buffer under this read, and nothing may hand it
            // back or resize it while this stands.
            bool reading = false;
            struct statx stx {
            };
        };
        std::unique_ptr<FileIo> file_io;
        // The kernel reads from this memory while a stream or a connection
        // may end, so it lives here and not on the App's connection.
        std::string spill_out;
        // One spill write flies per connection: the kernel reads the buffer
        // above, and a second write would swap it out under the first.
        bool spill_writing = false;

        // kMsgIovInline is four because an h1 answer plans three segments
        // and an h2 one nine. The heap is for the round that does not fit.
        static constexpr unsigned kMsgIovMax = App::Plan::kSegs + 1;
        static constexpr unsigned kMsgIovInline = 4;
        size_t plan_byte_total = 0;
        struct msghdr msg {
        };

        unsigned msg_iovlen = 0;
        unsigned msg_iov_cap = kMsgIovInline;
        size_t out_sent = 0;
        uint16_t gen = 0;
        uint8_t listener = 0;
        bool live = false;
        bool sending = false;
        bool close_after_send = false;
        // The kernel is writing into the App's buffer, so the close waits
        // for the read to land.
        bool close_owed = false;
        bool idle = false;

        typename App::Conn app;

        struct iovec msg_iov_inline[kMsgIovInline];
        std::unique_ptr<struct iovec[]> msg_iov_heap;
        struct iovec *iov()
        {
            return msg_iov_heap ? msg_iov_heap.get() : msg_iov_inline;
        }

    };

    // `what` is always a string literal: the once-only reporting keys on
    // the pointer.
    struct ConnFailed {
        const char *what;
        int err;
    };
    [[noreturn]] static void conn_failed(const char *what, int out_error = 0)
    {
        throw ConnFailed{what, out_error};
    }

    // Without an error log these fall to stderr, once per distinct reason,
    // so a peer cannot provoke a line per attempt.
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
        // mrb_noreturn resolves to nothing under -std=c++20, so the compiler
        // cannot see that mrb_raise does not return.
        WM_UNREACHABLE();
    }

    // %d, %i, %s and %v are mrb_format's, not printf's.
    template <typename... Args> [[noreturn]] void fatalf(const char *fmt, Args... args)
    {
        mrb_raisef(mrb_, E_WM_ERROR(mrb_), fmt, args...);
        WM_UNREACHABLE();
    }

    // The ring owns the block: no scope and no smart pointer can say when
    // the kernel has let go.
    Conn *conn_new(uint32_t listener_index, uint32_t descriptor)
    {
        Conn *const conn = new Conn();
        conn->fd = descriptor;
        conn->listener = static_cast<uint8_t>(listener_index);
        conn->deadline_s = now_s_ + header_timeout_;
        conn->app.reset(static_cast<uint8_t>(listener_index),
                        !unix_listener_[listener_index]);
        conn->live_next = live_head_;
        if (live_head_ != nullptr)
            live_head_->live_prev = conn;
        live_head_ = conn;
        live_++;
        return conn;
    }

    // Called only where the kernel holds nothing of this connection and
    // the peer is gone.
    void conn_free(Conn *conn) noexcept
    {
        if (conn->live_prev != nullptr)
            conn->live_prev->live_next = conn->live_next;
        else
            live_head_ = conn->live_next;
        if (conn->live_next != nullptr)
            conn->live_next->live_prev = conn->live_prev;
        if (live_ != 0)
            live_--;
        delete conn;
        // Only a note: this runs from destructors, and a function a
        // destructor calls may not raise.
        accept_retry_owed_ = true;
    }

    // The one place that counts a reference. Two doors is how a tally goes
    // wrong, and a wrong tally frees a block the kernel still names.
    uint64_t arm(Op &op, Conn *conn, uint8_t kind, uint32_t aux = 0)
    {
        op.conn = conn;
        op.kind = kind;
        op.aux = aux;
        if (conn != nullptr)
            conn->armed++;
        return reinterpret_cast<uint64_t>(&op);
    }

    // A reference the kernel does not hold, counted the same way: the
    // block may not go while anything names it.
    void hold(Conn &conn)
    {
        conn.armed++;
    }

    // A later completion of the same batch may free the connection, so
    // the entry is a counted reference.
    void rearm_hold(Conn &conn)
    {
        hold(conn);
        rearm_.push_back({&conn});
    }

    struct Released {
        Ring *ring;
        Op *op;
        const struct io_uring_cqe *completion;
        ~Released()
        {
            ring->release(*op, completion);
        }
    };

    struct Held {
        Ring *ring;
        Conn *conn;
        ~Held()
        {
            if (conn != nullptr)
                ring->drop_hold(*conn);
        }
    };

    // The entry is a counted reference, so the block stands until the loop
    // has read it.
    struct Rearm {
        Conn *conn;
    };

    struct Seen {
        struct io_uring *ring;
        struct io_uring_cqe *completion;
        ~Seen()
        {
            io_uring_cqe_seen(ring, completion);
        }
    };

    struct HeldList {
        Ring *ring;
        std::vector<Rearm> *owed;
        ~HeldList()
        {
            for (const Rearm &r : *owed)
                ring->drop_hold(*r.conn);
            owed->clear();
        }
    };

    void drop_hold(Conn &conn) noexcept
    {
        if (mrb_unlikely(conn.armed == 0)) {
            // The tally is wrong. This cannot raise: the callers are destructors.
            std::fputs("webmachine: a reference was given back that nobody held - "
                       "the reactor's tally is wrong and a block may already be gone\n",
                       stderr);
            std::abort();
        }
        conn.armed--;
        if (conn.dead && conn.armed == 0)
            conn_free(&conn);
    }

    // A multishot op keeps its reference while IORING_CQE_F_MORE says more
    // completions follow, and gives it back once.
    void release(Op &op, const struct io_uring_cqe *completion) noexcept
    {
        if ((completion->flags & IORING_CQE_F_MORE) != 0)
            return;
        Conn *const conn = op.conn;
        if (conn == nullptr)
            return;
        drop_hold(*conn);
    }

    struct io_uring_sqe *sqe_or_submit()
    {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_);
        if (mrb_likely(sqe != nullptr))
            return sqe;
        return sqe_or_raise(mrb_, &ring_);
    }

    static constexpr uint32_t kStreamAccess = 0;
    static constexpr uint32_t kStreamError = 1;

    void flush_log()
    {
        flush_access();
        flush_error();
    }

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
        io_uring_sqe_set_data64(sqe, arm(op_log_[kLogAccess], nullptr, detail::kLog, kStreamAccess));
    }

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
        io_uring_sqe_set_data64(sqe, arm(op_log_[kLogErrorHead], nullptr, detail::kLog, (1u << 16) | kStreamError));
        sqe = sqe_or_submit();
        io_uring_prep_send(sqe, err_fd_, element->flight.data() + sizeof(ErrRec),
                           element->flight.size() - sizeof(ErrRec), MSG_NOSIGNAL | MSG_WAITALL);
        io_uring_sqe_set_data64(sqe, arm(op_log_[kLogErrorBody], nullptr, detail::kLog, kStreamError));
    }

    // Every formatted line lands, so a refused write raises.
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

    // Idempotent, or a later accept would lose its slot.
    void close_listeners()
    {
        if (listeners_closed_)
            return;
        listeners_closed_ = true;
        for (uint32_t i = 0; i < nlisteners_; i++) {
            // The multishot accept holds the listening socket itself, so the
            // close alone leaves it in LISTEN. The accept is cancelled first.
            struct io_uring_sqe *sqe = sqe_or_submit();
            io_uring_prep_cancel64(sqe, reinterpret_cast<uint64_t>(&op_accept_[i]), 0);
            io_uring_sqe_set_data64(sqe,
                                    arm(op_poll_remove_, nullptr, detail::kPollRemove));
            sqe = sqe_or_submit();
            io_uring_prep_close_direct(sqe, listener_base_ + i);
            io_uring_sqe_set_data64(
                sqe, arm(op_listener_close_[i], nullptr, detail::kClose, listener_base_ + i));
        }
        io_uring_submit(&ring_);
    }

    void arm_accept(uint32_t listener_index)
    {
        if (draining_)
            return;
        accept_stalled_[listener_index] = false;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_multishot_accept_direct(sqe, listener_base_ + listener_index, nullptr,
                                              nullptr, 0);
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(
            sqe, arm(op_accept_[listener_index], nullptr, detail::kAccept, listener_index));
    }

    void arm_recv(Conn &c)
    {
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_recv_multishot(sqe, static_cast<int>(c.fd), nullptr, 0, 0);
        sqe->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
        sqe->buf_group = kBufGroup;
        if (bundles_)
            sqe->ioprio |= IORING_RECVSEND_BUNDLE;
        io_uring_sqe_set_data64(sqe, arm(c.op_recv, &c, detail::kRecv));
    }

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

    // MSG_WAITALL: the kernel finishes a short send itself, so the round
    // is one operation. The lent String is rooted until the round drains;
    // zc_release hands it back.
    void arm_send(Conn &c)
    {
        // One round, one deadline. A deadline refreshed per partial send
        // lets a slow peer hold the round for as long as it likes.
        c.deadline_s = now_s_ + send_timeout_;
        struct io_uring_sqe *sqe = sqe_or_submit();
        const int flags = MSG_NOSIGNAL | MSG_WAITALL | (app_.pending(c.app) ? MSG_MORE : 0);
        if (c.msg_iovlen == 0) {
            io_uring_prep_send(sqe, static_cast<int>(c.fd), c.out.data() + c.out_sent,
                               c.out.size() - c.out_sent, flags);
        } else if (c.msg_iovlen == 1) {
            // One segment needs no iovec. sendmsg imports the msghdr and the
            // vector, which a profile of one h1 run put at over 8 percent.
            const struct iovec *const entry = c.iov();
            io_uring_prep_send(sqe, static_cast<int>(c.fd), entry[0].iov_base, entry[0].iov_len,
                               flags);
        } else {
            c.msg = msghdr{};
            c.msg.msg_iov = c.iov();
            c.msg.msg_iovlen = c.msg_iovlen;
            io_uring_prep_sendmsg(sqe, static_cast<int>(c.fd), &c.msg, flags);
        }
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, arm(c.op_send, &c, detail::kSend));
        c.sending = true;
    }

    // shutdown before close_direct: close_direct alone never sends the
    // peer a FIN.
    void begin_close(Conn &c)
    {
        if (c.dead)
            return;
        if (c.sending) {
            c.close_after_send = true;
            return;
        }
        // A transfer that dies under a client is owed its log line too.
        app_.file_abandon(c.app);
        c.dead = true;
        // A file read into this connection's buffer is with the kernel;
        // the close waits for it.
        if (c.file_io != nullptr && c.file_io->reading) {
            c.close_owed = true;
            return;
        }
        finish_close(c);
    }

    void finish_close(Conn &c)
    {
        c.close_owed = false;
        if (io_uring_sq_space_left(&ring_) < 2)
            io_uring_submit(&ring_);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_shutdown(sqe, static_cast<int>(c.fd), SHUT_RDWR);
        sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(sqe, arm(c.op_shutdown, &c, detail::kShutdown));
        sqe = sqe_or_submit();
        io_uring_prep_close_direct(sqe, c.fd);
        io_uring_sqe_set_data64(sqe, arm(c.op_close, &c, detail::kClose));
    }

    // Which place takes the next peer. This ring is one of the places:
    // it accepts, and it answers what it keeps. The others are the
    // answering threads, and a peer reaches one of them through
    // IORING_OP_MSG_RING, which is the only way to hand over a direct
    // descriptor - it has no number another ring could take.
    //
    // The places take one each, in turn. What this replaced asked the
    // kernel for the peer's name first - SO_PEERCRED on a unix socket,
    // getsockname on a TCP socket - and hashed that name, so every
    // connection one peer opened met one thread. It cost one submission
    // and one completion per accepted connection, and it decided by a
    // hash of a name nobody chooses: two client processes on two
    // answering threads left one thread idle in four runs out of seven,
    // and the row read 91 percent where 200 was the ceiling.
    //
    // nworkers_ is this ring's own place, because the threads hold 0 to
    // nworkers_ - 1.
    uint32_t place_of_next_peer()
    {
        const uint32_t place = next_place_;
        next_place_++;
        if (next_place_ > nworkers_)
            next_place_ = 0;
        return place;
    }

    void hand_to_worker_at(uint32_t listener_index, uint32_t descriptor, uint32_t worker)
    {
        const int target = *std::next(worker_ring_fds_, static_cast<std::ptrdiff_t>(worker));
        const uint64_t tag = unix_listener_[listener_index] ? detail::kAdoptUnix : detail::kAdoptTcp;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_msg_ring_fd_alloc(sqe, target, static_cast<int>(descriptor), tag, 0);
        sqe->flags |= IOSQE_IO_LINK;
        io_uring_sqe_set_data64(sqe, 0);
        // The link keeps the order: the send first, the close after it.
        sqe = sqe_or_submit();
        io_uring_prep_close_direct(sqe, descriptor);
        io_uring_sqe_set_data64(sqe, 0);
    }

    void on_adopt(struct io_uring_cqe *completion, bool is_unix)
    {
        if (completion->res < 0) {
            say_server_error(app_.error_log(), std::string("a peer an acceptor sent here was "
                                                           "refused: ") +
                                                   std::strerror(-completion->res));
            return;
        }
        unix_listener_[0] = is_unix;
        Conn &c = *conn_new(0, static_cast<uint32_t>(completion->res));
        if (!is_unix) {
            static const int kOne = 1;
            struct io_uring_sqe *sqe = sqe_or_submit();
            io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(c.fd),
                                   IPPROTO_TCP, TCP_NODELAY, const_cast<int *>(&kOne),
                                   sizeof(kOne));
            sqe->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data64(sqe, arm(c.op_setup, &c, detail::kSetup));
        }
        arm_meminfo(c);
        if (log_fd_ >= 0 && !is_unix)
            arm_peer(c);
        arm_recv(c);
    }

    void on_accept(Op &op, struct io_uring_cqe *completion)
    {
        const uint32_t listener_index = op.aux;
        const bool table_full =
            completion->res == -ENFILE || completion->res == -EMFILE;
        // A failed multishot accept is over. Re-armed on a full table it
        // fails again at once, and the reactor spins.
        if (!(completion->flags & IORING_CQE_F_MORE) && !table_full)
            arm_accept(listener_index);
        // A full table is overload, not a fault: conn_free arms the accept
        // again. The operator hears it once.
        if (completion->res < 0) {
            if (table_full) {
                accept_stalled_[listener_index] = true;
                if (!table_full_said_) {
                    table_full_said_ = true;
                    say_server_error(app_.error_log(),
                                     std::string("the registered descriptor table is full (") +
                                         std::strerror(-completion->res) +
                                         "); peers wait until it drains");
                }
            }
            return;
        }
        if (nworkers_ != 0) {
            const uint32_t place = place_of_next_peer();
            if (place != nworkers_) {
                hand_to_worker_at(listener_index, static_cast<uint32_t>(completion->res), place);
                return;
            }
        }
        Conn &c = *conn_new(listener_index, static_cast<uint32_t>(completion->res));
        if (!unix_listener_[listener_index]) {
            static const int kOne = 1;
            struct io_uring_sqe *sqe = sqe_or_submit();
            io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(c.fd),
                                   IPPROTO_TCP, TCP_NODELAY, const_cast<int *>(&kOne),
                                   sizeof(kOne));
            sqe->flags |= IOSQE_FIXED_FILE;
            io_uring_sqe_set_data64(sqe, arm(c.op_setup, &c, detail::kSetup));
        }
        arm_meminfo(c);
        if (log_fd_ >= 0 && !unix_listener_[listener_index])
            arm_peer(c);
        arm_recv(c);
    }

    struct Slot {
        Conn &conn;
    };

    struct Completed {
        Conn &conn;
        struct io_uring_cqe *cqe;
    };

    void on_recv_nothing_to_parse(Slot sqe, struct io_uring_cqe *completion)
    {
        Conn &c = sqe.conn;
        // Some kernels attach a buffer to a clean EOF. A buffer nobody hands
        // back is lost, and 2048 lost buffers end every recv in ENOBUFS.
        give_back_buffers(completion);
        if (completion->res == -ENOBUFS) {
            // A kernel that keeps the multishot armed owes more completions,
            // and a second recv on one socket delivers bytes out of order.
            if ((completion->flags & IORING_CQE_F_MORE) == 0)
                rearm_hold(c);
            return;
        }
        begin_close(c);
    }

    void on_recv_after_close(Conn &c, size_t total)
    {
        (void)c;
        replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
    }

    // Every completion takes at least one whole buffer, and a bundle takes
    // consecutive ones.
    void give_back_buffers(const struct io_uring_cqe *completion)
    {
        if (!(completion->flags & IORING_CQE_F_BUFFER))
            return;
        const size_t total = completion->res > 0 ? static_cast<size_t>(completion->res) : 0;
        size_t count = total == 0 ? 1 : (total + kBufSize - 1) / kBufSize;
        // Advancing the ring by more than was taken hands one buffer out twice.
        count = std::min(count, static_cast<size_t>(kBufCount));
        replenish_ += static_cast<uint32_t>(count);
    }

    void on_recv(Conn &c, struct io_uring_cqe *completion)
    {
        // The buffers still go back, or the pool runs dry one closed
        // connection at a time.
        if (mrb_unlikely(c.dead)) {
            give_back_buffers(completion);
            return;
        }

        if (mrb_unlikely(completion->res <= 0)) {
            on_recv_nothing_to_parse({c}, completion);
            return;
        }
        if (mrb_unlikely(!(completion->flags & IORING_CQE_F_BUFFER))) {
            begin_close(c);
            return;
        }
        const uint32_t bid0 = completion->flags >> IORING_CQE_BUFFER_SHIFT;
        const size_t total = static_cast<size_t>(completion->res);
        if (mrb_unlikely(bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize)) {
            give_back_buffers(completion);
            begin_close(c);
            return;
        }
        if (mrb_unlikely(c.close_after_send)) {
            on_recv_after_close(c, total);
            return;
        }
        // A tunnel owes no next head, so its clock is the idle one.
        const bool tunneled = app_.tunneled(c.app);
        if (mrb_unlikely(c.idle || tunneled)) {
            c.idle = false;
            c.deadline_s = now_s_ + (tunneled ? idle_timeout_ : header_timeout_);
        }

        // Counted before the App sees a byte: connection_feed may raise, and
        // a buffer nobody hands back is lost.
        replenish_ += static_cast<uint32_t>((total + kBufSize - 1) / kBufSize);
        std::string &sink = c.sending ? c.next : c.out;
        bool closing = false;
        size_t left = total;
        uint32_t bid = bid0;
        typename App::Plan req;
        req.byte_cap = c.round_cap;
        while (left > 0) {
            const size_t count = left < kBufSize ? left : kBufSize;
            size_t offset = 0;
            // bid is masked to kBufCount, so an overflow here is our own bug.
            if (mrb_unlikely(__builtin_mul_overflow(static_cast<size_t>(bid),
                                                    static_cast<size_t>(kBufSize), &offset))) {
                fatal("ring: a buffer id ran past the pool this process mapped");
            }
            const bool last = left <= kBufSize;
            typename App::Plan *plan = (last && !c.sending) ? &req : nullptr;
            if (!closing)
                closing = !app_.connection_feed(c.app, {pool_ + offset, count}, {sink, plan});
            // Multishot recv delivers while a send is in flight, so a peer that
            // stops reading grows `next` at its own rate.
            if (mrb_unlikely(!closing && sink.size() > kTunnelOutCap))
                closing = true;
            left -= count;
            bid = (bid + 1) & (kBufCount - 1);
        }

        if (!c.sending) {
            if (req.iovlen != 0) {
                take_plan(c, req);
                arm_send(c);
            } else if (!c.out.empty()) {
                arm_send(c);
            }
        }
        arm_file_open(c);
        arm_spill_write(c);
        arm_compute_task(c);
        arm_watchers(c);
        // A refusal this process spelled itself owes no completion, so
        // nothing else would collect it.
        if (mrb_unlikely(App::file_answerable(c.app) || App::run_resumable(c.app)) && !c.sending) {
            continue_conn(c);
        }
        if (mrb_unlikely(closing)) {
            round_closed(c);
            if (c.dead)
                return;
        }
        if (mrb_unlikely(!(completion->flags & IORING_CQE_F_MORE)))
            rearm_hold(c);
    }

    void round_closed(Conn &conn)
    {
        if (conn.sending)
            conn.close_after_send = true;
        else
            begin_close(conn);
    }

    void finish_round(Conn &c, typename App::Plan &request, bool closing)
    {
        if (!c.sending) {
            if (request.iovlen != 0) {
                take_plan(c, request);
                arm_send(c);
            } else if (!c.out.empty()) {
                arm_send(c);
            }
        }
        arm_file_open(c);
        arm_compute_task(c);
        // A refusal this process spelled itself owes no completion, so
        // nothing else would collect it.
        if (mrb_unlikely(App::file_answerable(c.app)) && !c.sending)
            continue_conn(c);
        if (mrb_unlikely(closing))
            round_closed(c);
    }

    void deliver(Conn &c, const char *data, size_t length, bool last)
    {
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
        finish_round(c, req, closing);
    }


    void on_send(Conn &c, struct io_uring_cqe *completion)
    {
        c.sending = false;
        // The close is already on its way, and nothing may spell a round on
        // a connection going back.
        if (mrb_unlikely(c.dead))
            return;

        if (mrb_unlikely(completion->res < 0)) {
            send_refused(c, completion->res);
            return;
        }
        // MSG_WAITALL means the kernel already retried, so a short send is a
        // dead peer. A half-written response has no restart point.
        const size_t took = static_cast<size_t>(completion->res);
        const size_t offered = c.msg_iovlen != 0 ? c.plan_byte_total : c.out.size() - c.out_sent;
        if (mrb_unlikely(took != offered)) {
            begin_close(c);
            return;
        }
        c.deadline_s = now_s_ + send_timeout_;
        c.out.clear();
        c.out_sent = 0;
        c.msg_iovlen = 0;
        c.plan_byte_total = 0;
        send_done(c);
    }

    void send_refused(Conn &conn, int out_error)
    {
        (void)out_error;
        begin_close(conn);
    }

    void send_done(Conn &c)
    {
        if (!c.next.empty()) {
            c.out.swap(c.next);
            arm_send(c);
            return;
        }
        if (app_.pending(c.app)) {
            arm_meminfo(c);
            return;
        }
        continue_conn(c);
    }

    // openat2 with RESOLVE_BENEATH: the confinement is the kernel's, so
    // there is no path math here.
    void arm_file_open(Conn &c)
    {
        if (mrb_likely(!App::file_waiting(c.app)))
            return;
        if (c.file_io != nullptr && c.file_io->reading)
            return;
        const char *path = app_.file_take(c.app);
        if (path == nullptr)
            return;
        if (c.file_io == nullptr)
            c.file_io.reset(new Conn::FileIo());
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_openat2(sqe, docroot_fd(), path,
                              const_cast<struct open_how *>(docroot_how()));
        io_uring_sqe_set_data64(sqe, arm(c.op_file_open, &c, detail::kFileOpen));
    }

    // One-shot, not multishot: a watcher changes its mask mid-wait (libpq,
    // hiredis), and a one-shot poll is re-armed with the new mask anyway.
    void arm_watchers(Conn &c)
    {
        int slot = -1;
        while (App::watch_take(c.app, &slot))
            arm_watch(c, slot);
    }

    void arm_watch(Conn &conn, int slot)
    {
        const int descriptor = App::watcher_descriptor(conn.app, slot);
        const unsigned mask = App::watcher_mask(conn.app, slot);
        if (descriptor < 0 || mask == 0)
            return;
        // The record comes first: io_uring_get_sqe moves the tail at once,
        // and a resize that raised after it leaves an entry with stale user_data.
        std::deque<Op> &watch = conn.slow_records().watch;
        if (watch.size() <= static_cast<size_t>(slot))
            watch.resize(static_cast<size_t>(slot) + 1);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_poll_add(sqe, descriptor, mask);
        const uint64_t text = arm(watch[static_cast<size_t>(slot)], &conn, detail::kWatch,
                                  static_cast<uint32_t>(slot));
        io_uring_sqe_set_data64(sqe, text);
        App::watcher_is_armed(conn.app, slot, &ring_, text);
        // The sweep reads whole seconds, so a fraction rounds up: a deadline
        // that fires early is a promise broken.
        const double quiet = App::watcher_quiet_seconds(conn.app, slot);
        if (quiet > 0.0) {
            const int64_t secs = static_cast<int64_t>(quiet) +
                                 (quiet > static_cast<double>(static_cast<int64_t>(quiet)) ? 1 : 0);
            App::watcher_armed_at(conn.app, slot, now_s_ + (secs > 0 ? secs : 1));
        }
        conn.w_deadline_s = App::watchers_soonest_deadline(conn.app);
    }

    void on_watch(Conn &c, uint8_t slot, struct io_uring_cqe *completion)
    {
        if (c.dead)
            return;
        // -ECANCELED is a poll this side removed at a deadline; the slot may
        // hold a new watcher by now.
        if (completion->res == -ECANCELED)
            return;
        App::watcher_is_unarmed(c.app, slot);
        // A failed poll means the descriptor is gone, so the run sees POLLERR.
        const unsigned revents = completion->res > 0 ? static_cast<unsigned>(completion->res)
                                                     : static_cast<unsigned>(POLLERR);
        step_watch(c, static_cast<int>(slot), App::watcher_event(c.app, slot, revents));
    }

    void step_watch(Conn &conn, int slot, typename App::WatchStep step)
    {
        switch (step) {
            case App::WatchStep::kWait:
            case App::WatchStep::kRearm:
                // Both arm again; the mask is read fresh either way.
                arm_watch(conn, slot);
                return;
            case App::WatchStep::kDone:
                App::watchers_drop_slot(conn.app, slot);
                conn.w_deadline_s = App::watchers_soonest_deadline(conn.app);
                if (!conn.sending)
                    continue_conn(conn);
                return;
        }
    }

    void arm_compute_task(Conn &c)
    {
        if (mrb_likely(!App::compute_task_waiting(c.app)))
            return;
        if (compute_.workers() == 0) {
            // Started on the first job and not at setup: a server whose runs
            // never stop carries no worker threads.
            const long cores = ::sysconf(_SC_NPROCESSORS_ONLN);
            const unsigned by_core = cores > 1 ? static_cast<unsigned>(cores - 1) : 1;
            const unsigned want = by_core;
            if (const char *why = compute_.start(want, kComputeDepth)) {
                conn_failed(why, -EAGAIN);
            }
        }
        // A connection can hold several stopped runs, one per h2 stream, so
        // the tag names the run and the job.
        int park = -1;
        while (App::park_take_pending(c.app, &park)) {
            for (int slot = 0; slot < App::Conn::kJobSlots; slot++) {
                std::string arg;
                unsigned code = 0;
                double deadline = 0.0;
                if (!App::compute_task_take(c.app, park, slot, &code, arg, &deadline))
                    continue;
                const size_t job = static_cast<size_t>(park) * App::Conn::kJobSlots +
                                   static_cast<size_t>(slot);
                typename Conn::Slow &slow = c.slow_records();
                if (slow.compute.size() <= job) {
                    slow.compute.resize(job + 1);
                    slow.compute_started.resize(job + 1);
                }
                // A park slot may be taken again while the last tenant's answer
                // is still with a worker, so the generation rides along.
                const uint32_t aux = (static_cast<uint32_t>(App::park_generation(c.app, park))
                                      << 16) |
                                     static_cast<uint32_t>(job);
                const uint64_t began =
                    deadline > 0.0
                        ? arm(slow.compute_started[job], &c, detail::kComputeStarted, aux)
                        : 0;
                const uint64_t answer =
                    arm(slow.compute[job], &c, detail::kComputeTask, aux);
                bool sent = false;
                try {
                    sent = compute_.submit(mrb_, &ring_, code, arg, deadline, answer, began);
                } catch (...) {
                    // Nothing answers for these two records, so their
                    // references go back here.
                    drop_hold(c);
                    if (began != 0)
                        drop_hold(c);
                    throw;
                }
                if (!sent) {
                    drop_hold(c);
                    if (began != 0)
                        drop_hold(c);
                    // Every slot taken: the run is told and answers 503 itself.
                    App::compute_task_refused(c.app, park);
                    if (!c.sending)
                        continue_conn(c);
                    return;
                }
            }
        }
    }

    // The deadline is execution time, so the timer is armed when a worker
    // begins the job and not when it was queued.
    void on_compute_started(Op &op)
    {
        unsigned slot = 0;
        uint16_t generation = 0;
        const uint64_t answer =
            reinterpret_cast<uint64_t>(&op.conn->slow_records().compute[op.aux & 0xffffu]);
        if (!compute_.slot_of_answer(answer, &slot, &generation))
            return;
        const double deadline = compute_.started(slot, generation);
        if (deadline > 0.0)
            arm_compute_deadline(slot, generation, deadline);
    }

    // The kernel reads the timespec at submit, so neither the record nor
    // the timespec may be written while the timeout is in the ring.
    void arm_compute_deadline(unsigned slot, uint16_t generation, double deadline)
    {
        if (deadline <= 0.0)
            return;
        size_t at = 0;
        while (at < deadlines_.size() && deadlines_[at].busy)
            at++;
        if (at == deadlines_.size()) {
            // Nothing is marked busy until the SQE is in the ring, so a raise
            // here leaves nothing half made.
            deadlines_.emplace_back();
        }
        Deadline &owed = deadlines_[at];
        owed.slot = slot;
        owed.generation = generation;
        const int64_t whole = static_cast<int64_t>(deadline);
        owed.when.tv_sec = whole;
        owed.when.tv_nsec = static_cast<long long>((deadline - static_cast<double>(whole)) * 1e9);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_timeout(sqe, &owed.when, 0, 0);
        // The whole index: a truncated one makes two live timeouts name one
        // record.
        io_uring_sqe_set_data64(sqe, arm(owed.op, nullptr, detail::kComputeDeadline,
                                         static_cast<uint32_t>(at)));
        owed.busy = true;
        compute_.name_deadline(slot, generation, reinterpret_cast<uint64_t>(&owed.op));

    }

    void on_compute_deadline(Op &op, const struct io_uring_cqe *completion)
    {
        const size_t at = op.aux;
        if (mrb_unlikely(at >= deadlines_.size()))
            fatal("ring: a compute deadline named a record this process never took");
        Deadline &owed = deadlines_[at];
        owed.busy = false;
        // Left standing, the next job to take this record would have its
        // timeout removed by the first job's answer.
        compute_.name_deadline(owed.slot, owed.generation, 0);
        if (completion->res == -ETIME)
            compute_.interrupt(owed.slot, owed.generation);
    }

    // Without the removal the record is held for a max_runtime the job
    // never used, and the pool grows with the job rate.
    void drop_compute_deadline(uint64_t timeout_tag)
    {
        if (timeout_tag == 0)
            return;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_timeout_remove(sqe, timeout_tag, 0);
        // The deadline's own completion frees the record, whether the
        // removal found the timeout or not.
        io_uring_sqe_set_data64(sqe, 0);
    }

    void arm_file_close(Conn &c, int descriptor)
    {
        if (descriptor < 0)
            return;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_close(sqe, descriptor);
        io_uring_sqe_set_data64(sqe, arm(c.op_file_close, &c, detail::kFileClose));
    }

    void file_wake(Conn &c)
    {
        if (!c.sending)
            continue_conn(c);
    }

    void arm_spill_write(Conn &c)
    {
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
        io_uring_sqe_set_data64(sqe, arm(c.op_spill_write, &c, detail::kSpillWrite));
    }

    void on_spill_write(Completed done)
    {
        Conn &c = done.conn;
        // A dead connection: the octets came from this reactor's buffer, so
        // nothing is handed back.
        c.spill_writing = false;
        if (c.dead) {
            c.spill_out.clear();
            return;
        }
        app_.spill_wrote(c.app, done.cqe->res, c.spill_out);
        c.spill_out.clear();
        arm_spill_write(c);
        if (!c.sending)
            continue_conn(c);
    }

    // Nothing is resumed here: the run needs a sink and a plan, and only
    // spell_next_round has them.
    void on_compute_task(Op &op, struct io_uring_cqe *completion)
    {
        (void)completion;
        Conn &c = *op.conn;
        const uint32_t aux = op.aux;
        const uint8_t park_gen = static_cast<uint8_t>(aux >> 16);
        const size_t job = static_cast<size_t>(aux & 0xffffu);
        const uint8_t park = static_cast<uint8_t>(job / App::Conn::kJobSlots);
        const uint8_t slot = static_cast<uint8_t>(job % App::Conn::kJobSlots);
        const uint64_t poll_tag = reinterpret_cast<uint64_t>(&op);
        ComputeAnswer answered;
        const bool have = compute_.take(poll_tag, &answered);
        drop_compute_deadline(answered.deadline_tag);
        if (!have) {
            // Our own bookkeeping gone wrong, so it is said and the run still
            // gets a 500.
            answered.raised = true;
            say_server_error(app_.error_log(),
                             "a compute answer arrived for a job the pool does not hold");
        }
        // A raise in a worker happened on another thread in another VM, so
        // it goes to the error log whole, even when the connection is gone.
        if (answered.raised && have) {
            fault_report(app_.error_log(), mrb_,
                         {answered.exception, answered.step, answered.worker_name,
                          !c.dead && c.peer != nullptr
                              ? std::string_view{reinterpret_cast<const char *>(&c.peer->addr),
                                                 static_cast<size_t>(c.peer->addrlen)}
                              : std::string_view{},
                          static_cast<uint16_t>(answered.over_deadline ? 500 : 503)});
        }
        // The answer is taken even for a dead connection: the slot is the
        // pool's and would stay busy.
        if (c.dead)
            return;
        // The park was taken again since this job was sent, so the answer
        // is another round's.
        if (App::park_generation(c.app, park) != park_gen)
            return;
        App::compute_task_answered(c.app, static_cast<int>(park), static_cast<int>(slot), answered);
        if (!c.sending)
            continue_conn(c);
    }

    // ENOENT, EXDEV, ELOOP and EACCES get one answer, so a probe for a
    // symlink or a traversal looks like a missing name.
    void on_file_open(Completed done)
    {
        struct io_uring_cqe *const cqe = done.cqe;
        Conn &c = done.conn;
        if (c.dead) {
            arm_file_close(c, cqe->res >= 0 ? cqe->res : -1);
            return;
        }
        if (cqe->res < 0) {
            app_.file_reject(c.app);
            file_wake(c);
            return;
        }
        c.file_io->fd = cqe->res;
        c.file_io->filled = 0;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_statx(sqe, c.file_io->fd, "", AT_EMPTY_PATH,
                            STATX_TYPE | STATX_SIZE | STATX_MTIME, &c.file_io->stx);
        io_uring_sqe_set_data64(sqe, arm(c.op_file_stat, &c, detail::kFileStat));
    }

    void on_file_stat(Completed done)
    {
        struct io_uring_cqe *const cqe = done.cqe;
        Conn &c = done.conn;
        const int fd = c.file_io->fd;
        c.file_io->fd = -1;
        if (c.dead) {
            arm_file_close(c, fd);
            return;
        }
        if (cqe->res < 0) {
            arm_file_close(c, fd);
            app_.file_reject(c.app);
            file_wake(c);
            return;
        }
        size_t want = 0;
        const bool read_owed = app_.file_stat(c.app, c.file_io->stx, &want);
        if (!read_owed || want == 0) {
            arm_file_close(c, fd);
            if (read_owed)
                app_.file_ready_now(c.app, 0);
            file_wake(c);
            return;
        }
        // A failed mmap is not an error: the read path serves the same
        // bytes, only slower.
        const size_t maplen = App::file_map_len(c.app);
        if (maplen != 0) {
            void *method = ::mmap(nullptr, maplen, PROT_READ, MAP_PRIVATE, fd, 0);
            if (method != MAP_FAILED) {
                arm_file_close(c, fd);
                app_.file_mapped(c.app, static_cast<const char *>(method), maplen);
                file_wake(c);
                return;
            }
        }
        c.file_io->fd = fd;
        c.file_io->nbytes = want;
        c.file_io->filled = 0;
        c.file_io->offset = 0;
        c.file_io->stx_size = static_cast<size_t>(c.file_io->stx.stx_size);
        arm_file_read(c);
    }

    void arm_file_read(Conn &c)
    {
        char *chunk = app_.file_buffer(c.app, c.file_io->nbytes);
        c.file_io->reading = true;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_read(sqe, c.file_io->fd, chunk + c.file_io->filled,
                           static_cast<unsigned>(c.file_io->nbytes - c.file_io->filled),
                           c.file_io->offset + c.file_io->filled);
        io_uring_sqe_set_data64(sqe, arm(c.op_file_read, &c, detail::kFileRead));
    }

    void on_file_read(Completed done)
    {
        struct io_uring_cqe *const cqe = done.cqe;
        Conn &c = done.conn;
        c.file_io->reading = false;
        const int fd = c.file_io->fd;
        if (c.dead) {
            c.file_io->fd = -1;
            arm_file_close(c, fd);
            // Nothing writes the buffer now, so the close that waited may go on.
            if (c.close_owed)
                finish_close(c);
            return;
        }
        if (cqe->res < 0) {
            c.file_io->fd = -1;
            arm_file_close(c, fd);
            app_.file_error(c.app, std::strerror(-cqe->res));
            file_wake(c);
            return;
        }
        c.file_io->filled += static_cast<size_t>(cqe->res);
        if (cqe->res != 0 && c.file_io->filled < c.file_io->nbytes) {
            arm_file_read(c);
            return;
        }
        if (c.file_io->filled < c.file_io->nbytes) {
            // The file shrank under the Content-Length statx promised; the
            // framing would lie, so the answer is refused.
            c.file_io->fd = -1;
            arm_file_close(c, fd);
            app_.file_error(c.app, "the file shrank while it was read");
            file_wake(c);
            return;
        }
        c.file_io->offset += c.file_io->filled;
        if (c.file_io->offset >= c.file_io->stx_size) {
            c.file_io->fd = -1;
            arm_file_close(c, fd);
        }
        app_.file_ready_now(c.app, c.file_io->filled);
        file_wake(c);
    }

    void arm_meminfo(Conn &c)
    {
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_GETSOCKOPT, static_cast<int>(c.fd), SOL_SOCKET,
                               SO_MEMINFO, c.meminfo, sizeof(c.meminfo));
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, arm(c.op_meminfo, &c, detail::kMeminfo));
    }

    // The last argument of prep_cmd_getsockname picks the peer over the
    // socket's own name.
    void arm_peer(Conn &c)
    {
        if (c.peer == nullptr)
            c.peer.reset(new typename Conn::PeerAddr());
        c.peer->addrlen = sizeof(c.peer->addr);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_getsockname(sqe, static_cast<int>(c.fd),
                                      reinterpret_cast<struct sockaddr *>(&c.peer->addr),
                                      &c.peer->addrlen, 1);
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, arm(c.op_peer, &c, detail::kPeer));
    }
    void on_peer(Conn &c, struct io_uring_cqe *completion)
    {
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

    void on_meminfo(Conn &c, struct io_uring_cqe *completion)
    {
        // A recv error in the same batch may have closed this connection,
        // and a round must not be spelled onto a closing socket.
        if (mrb_unlikely(c.dead))
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
        continue_conn(c);
    }

    // A sink segment carries an offset, and this is the first moment its
    // address is final.
    void take_plan(Conn &conn, const typename App::Plan &request)
    {
        // What this round needs: kMsgIovMax is 1024 entries, 16 KB, and a
        // slow reader would hold it for as long as it stalls.
        const unsigned want = request.iovlen + 1;
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

    void continue_conn(Conn &c)
    {
        if (!c.out.empty()) {
            arm_send(c);
            return;
        }
        typename App::Plan req;
        req.byte_cap = c.round_cap;
        if (!app_.spell_next_round(c.app, c.out, req))
            c.close_after_send = true;
        arm_file_open(c);
        arm_spill_write(c);
        arm_compute_task(c);
        arm_watchers(c);
        if (req.iovlen != 0) {
            take_plan(c, req);
            arm_send(c);
            return;
        }
        if (!c.out.empty()) {
            arm_send(c);
            return;
        }
        // Only here is the lent window off the wire. Reading the next one on
        // the round that lent it overwrites bytes still being sent.
        if (c.file_io != nullptr && c.file_io->fd >= 0 && !c.file_io->reading &&
            c.file_io->offset < c.file_io->stx_size) {
            const size_t left = c.file_io->stx_size - c.file_io->offset;
            c.file_io->nbytes = left < kResponseFileWindow ? left : kResponseFileWindow;
            c.file_io->filled = 0;
            arm_file_read(c);
            return;
        }
        if (c.close_after_send) {
            c.close_after_send = false;
            begin_close(c);
            return;
        }
        c.idle = true;
        c.deadline_s = now_s_ + idle_timeout_;
        // Nothing is owed and nothing is on the wire, so the read buffer can
        // go back without pulling it from under anybody.
        if ((c.file_io == nullptr || !c.file_io->reading) && !app_.pending(c.app)) {
            App::file_release(c.app);
        }
    }
    void handle(struct io_uring_cqe *completion)
    {
        const uint64_t user_data = io_uring_cqe_get_data64(completion);
        if (user_data == 0)
            return;
        if (user_data == detail::kAdoptUnix || user_data == detail::kAdoptTcp) {
            on_adopt(completion, user_data == detail::kAdoptUnix);
            return;
        }
        if (user_data == detail::kAdoptStop) {
            stop_ = true;
            return;
        }
        Op &op = *reinterpret_cast<Op *>(user_data);
        Conn *const conn = op.conn;
        // A raise out of the ConnFailed handler is caught by no clause of
        // this try, so the reference goes back by destructor.
        const Released give_back{this, &op, completion};
        // The try is inline: a separate dispatch() takes on_send out of
        // line, measured at 5 percent.
        try {
            switch (op.kind) {
                case detail::kAccept:
                    on_accept(op, completion);
                    break;
                case detail::kRecv:
                    on_recv(*conn, completion);
                    break;
                case detail::kSend:
                    on_send(*conn, completion);
                    break;
                case detail::kMeminfo:
                    on_meminfo(*conn, completion);
                    break;
                case detail::kFileOpen:
                    on_file_open({*conn, completion});
                    break;
                case detail::kFileStat:
                    on_file_stat({*conn, completion});
                    break;
                case detail::kFileRead:
                    on_file_read({*conn, completion});
                    break;
                case detail::kFileClose:
                    break;
                case detail::kSpillWrite:
                    on_spill_write({*conn, completion});
                    break;
                case detail::kLog:
                    on_log(static_cast<uint16_t>(op.aux >> 16),
                           static_cast<uint32_t>(op.aux & 0xffffu), completion);
                    break;
                case detail::kPeer:
                    on_peer(*conn, completion);
                    break;
                case detail::kClose:
                    if (mrb_unlikely(completion->res == -ECANCELED && conn != nullptr)) {
                        struct io_uring_sqe *sqe = sqe_or_submit();
                        io_uring_prep_close_direct(sqe, conn->fd);
                        io_uring_sqe_set_data64(sqe,
                                                arm(conn->op_close, conn, detail::kClose));
                    }
                    break;
                case detail::kSetup:
                case detail::kShutdown:
                case detail::kPollRemove:
                    break;
                case detail::kComputeTask:
                    on_compute_task(op, completion);
                    break;
                case detail::kComputeDeadline:
                    on_compute_deadline(op, completion);
                    break;
                case detail::kComputeStarted:
                    on_compute_started(op);
                    break;
                case detail::kWatch:
                    on_watch(*conn, static_cast<uint8_t>(op.aux), completion);
                    break;
                case detail::kStop:
                    stop_ = true;
                    break;
                default:
                    break;
            }
        } catch (const ConnFailed &field) {
            if (conn != nullptr)
                connection_failed(*conn, field);
        }
    }

    void connection_failed(Conn &c, const ConnFailed &field)
    {
        say_connection_failed(field, c);
        begin_close(c);
    }

    // The wait is bounded to a second even without a budget, so the clocks
    // get a wake when nothing completes.
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
            if (::clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
                die_errno("clock_gettime(CLOCK_MONOTONIC_COARSE)", errno);
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
            if (::clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
                die_errno("clock_gettime(CLOCK_MONOTONIC_COARSE)", errno);
            now_s_ = static_cast<int64_t>(now.tv_sec);
        }
        app_.clock_tick();
        bool worked = false;
        struct io_uring_cqe *cqe = nullptr;
        while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
            {
                // Seen by destructor: a raise that left the completion in the
                // queue would dispatch it twice, and the second release frees
                // a freed block.
                const Seen done{&ring_, cqe};
                handle(cqe);
            }
            worked = true;
            if (bounded) {
                struct timespec now {
                };
                if (::clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
                    die_errno("clock_gettime(CLOCK_MONOTONIC_COARSE)", errno);
                if (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec >= *deadline)
                    break;
            }
        }
        if (!rearm_.empty()) {
            // Swapped out first: an arm_recv may raise, or close a connection
            // and append to the vector it walks.
            std::vector<Rearm> owed;
            owed.swap(rearm_);
            const HeldList give_back{this, &owed};
            while (!owed.empty()) {
                Conn &conn = *owed.back().conn;
                owed.pop_back();
                const Held one{this, &conn};
                if (!conn.dead && !conn.close_after_send)
                    arm_recv(conn);
            }
        }
        if (accept_retry_owed_ || now_s_ != last_reap_s_) {
            accept_retry_owed_ = false;
            for (uint32_t li = 0; li < nlisteners_; li++) {
                if (accept_stalled_[li])
                    arm_accept(li);
            }
        }
        if (now_s_ != last_reap_s_) {
            last_reap_s_ = now_s_;
            // The next link is read before the body, because the body may
            // free this connection.
            for (Conn *walk = live_head_; walk != nullptr;) {
                Conn &conn = *walk;
                walk = walk->live_next;
                {
                    if (conn.dead)
                        continue;
                    if (!conn.sending && app_.timed(conn.app)) {
                        conn.deadline_s = now_s_ + idle_timeout_;
                        continue_conn(conn);
                        continue;
                    }
                    // A watcher's deadline is not the connection's: the peer is
                    // fine, so this closes nothing.
                    if (conn.w_deadline_s != 0 && conn.w_deadline_s < now_s_) {
                        int over[16];
                        const size_t count =
                            App::watchers_over_deadline(conn.app, now_s_, over, 16);
                        for (size_t k = 0; k < count; k++) {
                            // The old poll goes first, by its tag, or it fires on
                            // the slot's successor.
                            const uint64_t armed = App::watcher_poll_tag(conn.app, over[k]);
                            if (armed != 0) {
                                struct io_uring_sqe *sqe = sqe_or_submit();
                                io_uring_prep_poll_remove(sqe, armed);
                                io_uring_sqe_set_data64(
                                    sqe, arm(conn.op_poll_remove, &conn, detail::kPollRemove));
                                App::watcher_is_unarmed(conn.app, over[k]);
                            }
                            step_watch(conn, over[k], App::watcher_deadline(conn.app, over[k]));
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
                            io_uring_prep_shutdown(sqe, static_cast<int>(conn.fd), SHUT_RDWR);
                            sqe->flags |= IOSQE_FIXED_FILE;
                            io_uring_sqe_set_data64(
                                sqe, arm(conn.op_shutdown, &conn, detail::kShutdown));
                        }
                    } else if (app_.going_away(conn.app, conn.out)) {
                        // RFC 6455 7.1.1: a WebSocket hears a Close frame before
                        // the socket goes.
                        conn.close_after_send = true;
                        arm_send(conn);
                    } else {
                        begin_close(conn);
                    }
                }
            }
        }
        if (draining_ && !stop_) {
            struct timespec now {
            };
            if (::clock_gettime(CLOCK_MONOTONIC_COARSE, &now) != 0)
                die_errno("clock_gettime(CLOCK_MONOTONIC_COARSE)", errno);
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
    mrb_state *mrb_ = nullptr;
    int backlog_ = SOMAXCONN;
    int header_timeout_ = 60;
    int send_timeout_ = 60;
    int idle_timeout_ = 75;
    int64_t now_s_ = 0;
    int64_t last_reap_s_ = 0;
    Conn *live_head_ = nullptr;
    // Process-owned records: `conn` is null, release() counts nothing, and
    // they live as long as the ring.
    Op op_stop_;
    Op op_poll_remove_;
    Op op_unlink_;
    enum : unsigned { kLogAccess = 0, kLogErrorHead = 1, kLogErrorBody = 2, kLogRecords = 3 };
    Op op_log_[kLogRecords];
    Op op_accept_[kMaxListeners];
    Op op_listener_close_[kMaxListeners];
    // One per (listener, stage), so each stage of a chain can say which
    // one refused.
    Op op_setup_[kMaxListeners][detail::kStUnlink + 1];
    std::vector<Rearm> rearm_;
    // A deque: the kernel holds the address of the record and the
    // timespec, and a vector moves them when it grows.
    struct Deadline {
        Op op;
        __kernel_timespec when {};
        unsigned slot = 0;
        uint16_t generation = 0;
        bool busy = false;
    };
    std::deque<Deadline> deadlines_;
    uint32_t table_size_ = 0;
    uint32_t listener_base_ = 0;
    bool unix_listener_[kMaxListeners] = {};
    bool accept_stalled_[kMaxListeners] = {};
    bool table_full_said_ = false;
    // The note is made where a raise cannot go and read where one can.
    bool accept_retry_owed_ = false;
    static constexpr unsigned kSaidMax = 24;
    const char *said_[kSaidMax] = {};
    unsigned said_count_ = 0;
    int bound_port_[kMaxListeners] = {};
    std::vector<std::string> unix_paths_;
    uint32_t nlisteners_ = 0;
    bool listeners_closed_ = false;
    // This ring chooses the worker itself; the kernel's choice on a shared
    // listener was uneven.
    const int *worker_ring_fds_ = nullptr;
    uint32_t nworkers_ = 0;
    uint32_t next_place_ = 0;
    bool draining_ = false;
    int64_t drain_deadline_ = 0;
    uint32_t live_ = 0;
    char *pool_ = nullptr;
    ComputePool compute_;
    struct io_uring_buf_ring *buf_ring_ = nullptr;
    unsigned replenish_ = 0;
    // Entry i of the ring holds buffer i, so a bundle's buffers are
    // consecutive ids.
    uint32_t buf_tail_ = 0;
    bool bundles_ = false;
    bool rewrite_entries_ = false;

    // A kernel before 7.1 shortens a bundle's last entry to the bytes it
    // had and leaves it short (io_uring/kbuf: don't truncate end buffer
    // for bundles). There a returned buffer goes back as a whole entry.
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
};

} // namespace webmachine

#endif
