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
#include <deque>

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
        if (ring_up_) {
            close_listeners();
            // Each unlink is waited for by its own completion. A count alone
            // is wrong here: the listener closes submitted just above complete
            // too, and a wait that took those for the unlinks returned before
            // the unlink ran. The ring exit then cancelled the queued unlink,
            // and the path stayed - which is what the floor bintest saw under
            // the sanitizer.
            const uint64_t unlink_tag = arm(op_unlink_, nullptr, detail::kSetup, detail::kStUnlink);
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
        if (ring_up_) {
            io_uring_queue_exit(&ring_);
            ring_up_ = false;
        }
        // #113: the ring is gone, so the kernel names nothing of these any
        // more. Whatever it still held is freed here and nowhere else.
        while (live_head_ != nullptr)
            conn_free(live_head_);
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
        // #113: the size of the registered descriptor table, not a count of
        // slots of ours. The kernel picks the entry for every accept and we
        // never index anything by it.
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
            mrb_raisef(mrb_, E_WM_ERROR(mrb_), "register_files_sparse(%d): %s",
                       static_cast<int>(table_size_ + kMaxListeners), std::strerror(-rc));
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

    // Every setup step wants an SQE and none of them can go on without one.
    struct io_uring_sqe *setup_sqe()
    {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_);
        if (sqe == nullptr)
            mrb_raise(mrb_, E_WM_ERROR(mrb_), "SQ empty at setup");
        return sqe;
    }

    // Loop until the stop signal's completion lands.
    // The acceptor says the stop to every ring it feeds. A ring that
    // answers what it is sent has no stop signal of its own: the signalfd
    // is the acceptor's, and this is how the word reaches the others.
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

    // The registered descriptor table's size - what this machine allows.
    uint32_t max_conns() const
    {
        return table_size_;
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
        if (want.fd >= 0) {
            // The caller listens, this registers. A worker process reaches
            // here with the descriptor its parent made, so it binds
            // nothing, listens on nothing, and unlinks nothing: the parent
            // owns the path and the port.
            const int inherited = want.fd;
            const int rc = io_uring_register_files_update(&ring_, slot, &inherited, 1);
            if (rc < 0) {
                mrb_raisef(mrb_, E_WM_ERROR(mrb_), "listener %d: register the inherited socket: %s",
                           static_cast<int>(listener_index), std::strerror(-rc));
            }
            unix_listener_[listener_index] = is_unix;
            bound_port_[listener_index] = is_unix ? 0 : want.port;
            return;
        }
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

                sqe = setup_sqe();
                io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, slot, SOL_SOCKET,
                                       SO_REUSEPORT, const_cast<int *>(&kOne), sizeof(kOne));
                sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
                io_uring_sqe_set_data64(sqe, arm(op_setup_[listener_index][detail::kStReuseport], nullptr,
                                                 detail::kSetup, detail::kStReuseport));
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
    struct Conn;

    // One operation the kernel can complete, and the whole of what a
    // completion says about itself.
    //
    // Its address is the SQE's user_data. Which member of a connection it
    // is names the operation - `kind` says which - and `conn` says whose.
    // Nothing is packed into the pointer and nothing is numbered: the
    // allocator gives each operation an address of its own, and an address
    // belongs to one object for exactly as long as that object exists.
    //
    // `aux` carries what a kind needs beyond that: the listener index on an
    // accept, which watcher on a poll, which job on a worker's answer. An
    // accept has no connection yet, so its `conn` is null.
    struct Op {
        Conn *conn = nullptr;
        uint32_t aux = 0;
        uint8_t kind = 0;
    };

    struct Conn {
        // The direct descriptor the kernel chose for this peer. We never
        // pick one: multishot_accept_direct allocates from the registered
        // table and hands the entry back in cqe->res.
        uint32_t fd = 0;
        // What the kernel and the workers still hold of this connection.
        // It rises when an operation is submitted and falls when the
        // kernel says that operation is over - a CQE without
        // IORING_CQE_F_MORE, or a worker's answer. The block is freed when
        // it reaches zero and the connection is dead, and never before:
        // a completion that named a freed address is the one fault this
        // design may not have.
        uint32_t armed = 0;
        // The peer is gone and nothing more will be armed. The block still
        // stands until `armed` reaches zero.
        bool dead = false;
        // #113: the live list, so the idle sweep and the drain can walk
        // what exists. There is no table to walk any more.
        Conn *live_prev = nullptr;
        Conn *live_next = nullptr;
        // #30: a watcher and a compute job are not one per connection, so
        // they are not members. They grow to what this connection actually
        // uses and no further - there is no ceiling of 256 or of 16.
        //
        // A deque and not a vector: the SQE carries the address of the
        // record, so a record that moves while the kernel names it is a
        // use after free. A deque never moves an element that is already
        // in it when the deque grows at the back; a vector does.
        //
        // Behind a pointer, and made on the first watcher or the first
        // job: a deque allocates when it is made, and nearly every
        // connection this server sees has neither. Three of them inline
        // was three allocations and 240 bytes per peer for nothing.
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
        // #30: when the watcher this connection's stopped run waits on has
        // been quiet for as long as it allowed. 0 = nothing is armed. It is
        // Not deadline_s: the peer on this socket is fine, some other
        // descriptor is the quiet one, and nothing here closes anything.
        // #30: the earliest deadline any watcher of this connection owes.
        // Each watcher keeps its own - the App has them, one per Ruby
        // object - and this is only what the sweep has to read.
        int64_t w_deadline_s = 0;

        // One per operation that can fly at the same time as another. Each
        // has its own address, which is what the SQE carries. Below the
        // fields a request reads, on purpose: arming and releasing touch
        // one of these, and the round touches the rest of the block.
        Op op_recv;
        Op op_send;
        Op op_setup;
        Op op_meminfo;
        Op op_peer;
        Op op_shutdown;
        Op op_close;
        // #30: the removal of a watcher's poll at its deadline. Its own
        // record, because the close of this connection may be in flight.
        Op op_poll_remove;
        Op op_file_open;
        Op op_file_stat;
        Op op_file_read;
        Op op_file_close;
        Op op_spill_write;

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

    // A peer arrived. The connection is one block, made here and freed in
    // one place, and the ring owns it: no scope and no smart pointer can
    // say when the kernel has let go, so neither holds it.
    Conn *conn_new(uint32_t listener_index, uint32_t descriptor)
    {
        Conn *const conn = new Conn();
        conn->fd = descriptor;
        conn->listener = static_cast<uint8_t>(listener_index);
        conn->deadline_s = now_s_ + header_timeout_;
        conn->app.reset(static_cast<uint8_t>(listener_index),
                        !unix_listener_[listener_index]);
        // #113: the live list. Nothing enumerates connections any more, so
        // the sweep and the drain walk this.
        conn->live_next = live_head_;
        if (live_head_ != nullptr)
            live_head_->live_prev = conn;
        live_head_ = conn;
        live_++;
        return conn;
    }

    // The kernel holds nothing of this connection any more, and the peer is
    // gone. Called from release() and from nowhere else, because release()
    // is the only thing that knows when both are true.
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
        // An entry of the registered table is free again, so a listener
        // that stopped on a full table may take peers once more. Only the
        // note is made here: this runs from destructors of its own, and a
        // function a destructor calls may not raise.
        accept_retry_owed_ = true;
    }

    // The one door an operation goes through, and the only place that
    // names one. The SQE carries the address of the connection's own
    // record for this operation, and the connection counts the reference
    // the kernel now holds.
    //
    // Counting has to happen here and nowhere else. Two doors is how a
    // tally goes wrong, and a wrong tally is a block freed while the
    // kernel still names it.
    uint64_t arm(Op &op, Conn *conn, uint8_t kind, uint32_t aux = 0)
    {
        op.conn = conn;
        op.kind = kind;
        op.aux = aux;
        if (conn != nullptr)
            conn->armed++;
        return reinterpret_cast<uint64_t>(&op);
    }

    // A reference the kernel does not hold: an operation this reactor has
    // taken but not yet submitted, or a re-arm it owes itself. It is
    // counted the same way, because the block may not go while anything
    // still names it.
    void hold(Conn &conn)
    {
        conn.armed++;
    }

    // #113: a recv this reactor owes itself. The connection may be closed
    // and freed by a later completion of the same batch, so the entry is a
    // counted reference like any other and the block stands until the loop
    // has read it.
    void rearm_hold(Conn &conn)
    {
        hold(conn);
        rearm_.push_back({&conn});
    }

    // The reference an operation's completion carries, given back however
    // the scope ends. release() is noexcept, so this destructor is too.
    struct Released {
        Ring *ring;
        Op *op;
        const struct io_uring_cqe *completion;
        ~Released()
        {
            ring->release(*op, completion);
        }
    };

    // A reference given back however the scope ends, a raise included.
    // Every other way of saying it has been tried here and every one of
    // them has a path that unwinds past the line that counts down.
    struct Held {
        Ring *ring;
        Conn *conn;
        ~Held()
        {
            if (conn != nullptr)
                ring->drop_hold(*conn);
        }
    };

    // Which connection owes a fresh recv. The entry is a counted
    // reference, so the block stands until the loop has read it.
    struct Rearm {
        Conn *conn;
    };

    // A completion taken out of the queue however the scope ends.
    struct Seen {
        struct io_uring *ring;
        struct io_uring_cqe *completion;
        ~Seen()
        {
            io_uring_cqe_seen(ring, completion);
        }
    };

    // The rest of a list of references, when the walk over it ended early.
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

    // The one place a reference goes back, whoever held it.
    void drop_hold(Conn &conn) noexcept
    {
        if (mrb_unlikely(conn.armed == 0)) {
            // The tally is wrong, so a block may already have been freed
            // while the kernel still names it. This cannot be raised: the
            // callers are destructors, and it is not the application's
            // fault to catch. The process says why it goes and goes.
            std::fputs("webmachine: a reference was given back that nobody held - "
                       "the reactor's tally is wrong and a block may already be gone\n",
                       stderr);
            std::abort();
        }
        conn.armed--;
        if (conn.dead && conn.armed == 0)
            conn_free(&conn);
    }

    // The kernel has finished with this operation. A multishot one is not
    // finished while IORING_CQE_F_MORE says more completions follow, so it
    // keeps its reference across every one of them and gives it back once.
    //
    // One counted submission is released exactly once. That is the whole
    // invariant this design stands on.
    void release(Op &op, const struct io_uring_cqe *completion) noexcept
    {
        if ((completion->flags & IORING_CQE_F_MORE) != 0)
            return;
        Conn *const conn = op.conn;
        if (conn == nullptr)
            return;
        drop_hold(*conn);
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
        io_uring_sqe_set_data64(sqe, arm(op_log_[kLogAccess], nullptr, detail::kLog, kStreamAccess));
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
        io_uring_sqe_set_data64(sqe, arm(op_log_[kLogErrorHead], nullptr, detail::kLog, (1u << 16) | kStreamError));
        sqe = sqe_or_submit();
        io_uring_prep_send(sqe, err_fd_, element->flight.data() + sizeof(ErrRec),
                           element->flight.size() - sizeof(ErrRec), MSG_NOSIGNAL | MSG_WAITALL);
        io_uring_sqe_set_data64(sqe, arm(op_log_[kLogErrorBody], nullptr, detail::kLog, kStreamError));
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

    // Multishot accept_direct against the fixed listener slot.
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

    // Multishot recv out of the buffer ring, bundles where the kernel
    // offers them. One shape, because this build has no record layer: a
    // connection is cleartext or it never started.
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
    // MSG_WAITALL: the kernel finishes a short send itself, so the round is
    // one operation and there is no offset to carry.
    //
    // The lend survives it: resource.cpp freezes and roots the String and
    // zc_release hands it back when the round drains, never when one send
    // returns.
    void arm_send(Conn &c)
    {
        // One round, one deadline. A plaintext send is MSG_WAITALL and comes
        // back once, so this is the same rule both paths follow; an
        // offloaded one comes back per partial, and refreshing the deadline
        // there let a peer that opens its window one octet at a time hold
        // the round, its lent body and its slot for as long as it liked.
        c.deadline_s = now_s_ + send_timeout_;
        struct io_uring_sqe *sqe = sqe_or_submit();
        const int flags = MSG_NOSIGNAL | MSG_WAITALL | (app_.pending(c.app) ? MSG_MORE : 0);
        if (c.msg_iovlen == 0) {
            io_uring_prep_send(sqe, static_cast<int>(c.fd), c.out.data() + c.out_sent,
                               c.out.size() - c.out_sent, flags);
        } else if (c.msg_iovlen == 1) {
            // One segment is one buffer, and a buffer does not need an iovec.
            // sendmsg makes the kernel copy an msghdr in from user space and
            // import the vector behind it - io_msg_copy_hdr, io_sendmsg_prep,
            // copy_iovec_from_user, __import_iovec - which a profile of one h1
            // run put at over 8% of everything. send carries a pointer and a
            // length and skips all of it.
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

    // shutdown before close_direct, linked: close_direct alone leaves the
    // socket open and the peer never sees FIN.
    void begin_close(Conn &c)
    {
        if (c.dead)
            return;
        if (c.sending) {
            c.close_after_send = true;
            return;
        }
        // A transfer dying under a client is exactly the event an operator
        // wants in the log, so the line is owed here too - with the bytes that
        // really went out.
        app_.file_abandon(c.app);
        c.dead = true;
        // A read of this connection's own buffer is with the kernel. The
        // close waits for it; on_file_read finishes it. A read of a regular
        // file ends, and the block is held only that long.
        if (c.file_io != nullptr && c.file_io->reading) {
            c.close_owed = true;
            return;
        }
        finish_close(c);
    }

    // The two ops that end a slot: the shutdown, and the close that frees
    // the fixed-table entry. begin_close submits them unless a file read
    // holds this connection's buffer, and on_file_read submits them when
    // that read lands.
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

    // A new peer: its slot, its clocks, and the setsockopts TCP wants.
    // The peer this ring accepted goes to the next worker's ring, and the
    // slot it held here goes back. IORING_OP_MSG_RING carries a registered
    // descriptor to another ring of this process and nothing else does:
    // the descriptor is direct, so it has no number a process could pass
    // by any other means.
    void hand_to_worker(uint32_t listener_index, uint32_t descriptor)
    {
        const int target = worker_ring_fds_[next_worker_];
        next_worker_++;
        if (next_worker_ == nworkers_)
            next_worker_ = 0;
        const uint64_t tag = unix_listener_[listener_index] ? detail::kAdoptUnix : detail::kAdoptTcp;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_msg_ring_fd_alloc(sqe, target, static_cast<int>(descriptor), tag, 0);
        sqe->flags |= IOSQE_IO_LINK;
        io_uring_sqe_set_data64(sqe, 0);
        // The worker holds the file now, so this ring's slot is spent. The
        // link keeps the order: the send first, the close after it.
        sqe = sqe_or_submit();
        io_uring_prep_close_direct(sqe, descriptor);
        io_uring_sqe_set_data64(sqe, 0);
    }

    // A connection an acceptor sent here. cqe->res is the descriptor this
    // ring's own table allocated for it, and the tag says what it was
    // accepted on, which is all this ring needs to know about a listener
    // it does not have.
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
        // The decision comes before the re-arm. A multishot accept that
        // failed is over, and arming it again on a full table makes it
        // fail again at once - the reactor then spins until a descriptor
        // comes free. So a refused accept waits for one instead.
        if (!(completion->flags & IORING_CQE_F_MORE) && !table_full)
            arm_accept(listener_index);
        // The kernel refused the peer. A full descriptor table is overload
        // and not a fault: the multishot accept stays armed above, the idle
        // clocks give entries back, and the next peer is taken. It is still
        // not hidden - the operator hears it once, with the number.
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
            hand_to_worker(listener_index, static_cast<uint32_t>(completion->res));
            return;
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

    // One completion's connection: the slot it names, and the slot itself.
    struct Slot {
        Conn &conn;
    };

    // One completion as the reactor hands it on: the connection slot it
    // names, the generation that slot was in when the op was armed, and the
    // completion itself.
    struct Completed {
        Conn &conn;
        struct io_uring_cqe *cqe;
    };

    // Wire bytes to the App. Kernel-supplied ids and lengths are checked
    // before use; ENOBUFS re-arms rather than hanging the connection.
    // Nothing arrived that can be parsed: a peer that left, a kernel that
    // ran out of buffers, a completion whose own numbers do not hold. None
    // of it is the path a request takes, so none of it is in one.
    void on_recv_nothing_to_parse(Slot sqe, struct io_uring_cqe *completion)
    {
        Conn &c = sqe.conn;
        // A completion that carries a buffer carries it even with no bytes.
        // Some kernels report one on a clean EOF, and a buffer nobody hands
        // back is a buffer this process has lost: 2048 such closes and every
        // recv answers ENOBUFS.
        give_back_buffers(completion);
        if (completion->res == -ENOBUFS) {
            // Only when the kernel has let this recv go. A kernel that
            // reports ENOBUFS and keeps the multishot armed owes more
            // completions, and a second recv on one socket would deliver
            // the same connection's bytes out of the parser's order.
            if ((completion->flags & IORING_CQE_F_MORE) == 0)
                rearm_hold(c);
            return;
        }
        begin_close(c);
    }

    // Bytes for a connection that has already been told to go: the buffers
    // still have to be handed back, and nothing else does.
    void on_recv_after_close(Conn &c, size_t total)
    {
        (void)c;
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
        size_t count = total == 0 ? 1 : (total + kBufSize - 1) / kBufSize;
        // A length the kernel cannot have meant still names at most the
        // whole pool. Advancing the ring by more entries than were taken
        // hands the same buffer out twice, which is worse than losing it.
        count = std::min(count, static_cast<size_t>(kBufCount));
        replenish_ += static_cast<uint32_t>(count);
    }

    void on_recv(Conn &c, struct io_uring_cqe *completion)
    {
        // A connection already told to go: the bytes are nobody's, and the
        // buffers still go back, or the pool runs dry one closed connection
        // at a time.
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
            // The buffers go back whatever the numbers said. A buffer
            // nobody hands back is one this process has lost, and 2048 of
            // them make every recv answer ENOBUFS for good.
            give_back_buffers(completion);
            begin_close(c);
            return;
        }
        if (mrb_unlikely(c.close_after_send)) {
            on_recv_after_close(c, total);
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

        // Every buffer of this completion, counted before the App sees a
        // byte. connection_feed runs the application's own code and may
        // raise; counting per iteration lost the rest of them when it did,
        // and a buffer nobody hands back is one this process has lost.
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
            // bid is masked to kBufCount above and kBufCount * kBufSize is
            // static_asserted to fit, so this cannot overflow. It is our own
            // bug if it does, and our own bugs are said rather than hidden.
            if (mrb_unlikely(__builtin_mul_overflow(static_cast<size_t>(bid),
                                                    static_cast<size_t>(kBufSize), &offset))) {
                fatal("ring: a buffer id ran past the pool this process mapped");
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
        }

        if (!c.sending) {
            if (req.iovlen != 0) {
                take_plan(c, req);
                arm_send(c);
            } else if (!c.out.empty()) {
                arm_send(c);
            }
        }
        // A run that named a file answered nothing yet: the open is the
        // reactor's, and its result reaches the wire through continue_conn.
        arm_file_open(c);
        arm_spill_write(c);
        arm_compute_task(c);
        arm_watchers(c);
        // Unless the name never reached the kernel at all - a refusal this
        // process spelled itself owes no completion, so nothing else would
        // ever come back to collect it.
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

    // The App will take nothing more on this connection.
    void round_closed(Conn &conn)
    {
        if (conn.sending)
            conn.close_after_send = true;
        else
            begin_close(conn);
    }

    // What a round owes once the App has seen its bytes: the answer on the
    // wire, an open the run deferred, and the close it may have asked for.
    // Shared, because bytes reach the App from three places - the buffer
    // ring, an offloaded socket's recvmsg, and the backlog a handshake left.
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
        // A run that named a file answered nothing yet: the open is the
        // reactor's, and its result reaches the wire through continue_conn.
        arm_file_open(c);
        arm_compute_task(c);
        // Unless the name never reached the kernel at all - a refusal this
        // process spelled itself owes no completion, so nothing else would ever
        // come back to collect it.
        if (mrb_unlikely(App::file_answerable(c.app)) && !c.sending)
            continue_conn(c);
        if (mrb_unlikely(closing))
            round_closed(c);
    }

    // One contiguous stretch of plaintext to the App, and the round it
    // finishes. `last` is what lets a Plan form, so a caller that has the
    // whole of what arrived says so.
    void deliver(Conn &c, const char *data, size_t length, bool last)
    {
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
        finish_round(c, req, closing);
    }


    // What the kernel took, and what is still owed.
    void on_send(Conn &c, struct io_uring_cqe *completion)
    {
        c.sending = false;
        // The connection ended while this send was with the kernel. That it
        // is over is all this completion still means: the close is already
        // on its way, and nothing may spell a round on a connection going
        // back.
        if (mrb_unlikely(c.dead))
            return;

        if (mrb_unlikely(completion->res < 0)) {
            send_refused(c, completion->res);
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

    // A send the kernel refused outright.
    void send_refused(Conn &conn, int out_error)
    {
        (void)out_error;
        begin_close(conn);
    }

    // What a finished send leaves owed: the rest of the round, the next
    // one, or the connection going idle.
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

    // response.file, stage 1: openat2 against the docroot fd. RESOLVE_BENEATH
    // anchors the walk to that fd, so the confinement is the kernel's and not
    // this code's - no path math here, on purpose.
    void arm_file_open(Conn &c)
    {
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
        io_uring_sqe_set_data64(sqe, arm(c.op_file_open, &c, detail::kFileOpen));
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
        // The record comes first. io_uring_get_sqe moves the queue's tail at
        // once, so a resize that raised between the two would leave an entry
        // in the ring carrying whatever user_data sat in that slot before -
        // an address of some long freed block.
        std::deque<Op> &watch = conn.slow_records().watch;
        if (watch.size() <= static_cast<size_t>(slot))
            watch.resize(static_cast<size_t>(slot) + 1);
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_poll_add(sqe, descriptor, mask);
        const uint64_t text = arm(watch[static_cast<size_t>(slot)], &conn, detail::kWatch,
                                  static_cast<uint32_t>(slot));
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
    void on_watch(Conn &c, uint8_t slot, struct io_uring_cqe *completion)
    {
        if (c.dead)
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
        step_watch(c, static_cast<int>(slot), App::watcher_event(c.app, slot, revents));
    }

    void step_watch(Conn &conn, int slot, typename App::WatchStep step)
    {
        switch (step) {
            case App::WatchStep::kWait:
            case App::WatchStep::kRearm:
                // Both arm again - the mask is read fresh either way, so the two
                // differ only in what the reader learns from the name.
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
                const size_t job = static_cast<size_t>(park) * App::Conn::kJobSlots +
                                   static_cast<size_t>(slot);
                typename Conn::Slow &slow = c.slow_records();
                if (slow.compute.size() <= job) {
                    slow.compute.resize(job + 1);
                    slow.compute_started.resize(job + 1);
                }
                // The park generation rides along, because a park slot of
                // this connection may be taken again while an answer for the
                // last tenant is still with a worker. The address alone
                // cannot tell those apart - it is the same slot of the same
                // connection - so the run that owns it is named as well.
                const uint32_t aux = (static_cast<uint32_t>(App::park_generation(c.app, park))
                                      << 16) |
                                     static_cast<uint32_t>(job);
                // The started message is sent only where there is a
                // deadline to clock, so only there does a record name it.
                const uint64_t began =
                    deadline > 0.0
                        ? arm(slow.compute_started[job], &c, detail::kComputeStarted, aux)
                        : 0;
                const uint64_t answer =
                    arm(slow.compute[job], &c, detail::kComputeTask, aux);
                bool sent = false;
                try {
                    sent = compute_.submit(mrb_, code, arg, deadline, answer, began);
                } catch (...) {
                    // Nothing was sent, so nothing will answer for these two
                    // records. Their references go back here or the block
                    // stands for the life of the process.
                    drop_hold(c);
                    if (began != 0)
                        drop_hold(c);
                    throw;
                }
                if (!sent) {
                    drop_hold(c);
                    if (began != 0)
                        drop_hold(c);
                    // Every slot taken. Not a refusal this layer invents - the run
                    // is told, and it answers 503 the way it would answer anything
                    // else.
                    App::compute_task_refused(c.app, park);
                    if (!c.sending)
                        continue_conn(c);
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
    void on_compute_started(Op &op)
    {
        unsigned slot = 0;
        uint16_t generation = 0;
        // The answer tag names the job; the pool says which of its slots
        // holds it. Nothing here indexes a connection.
        const uint64_t answer =
            reinterpret_cast<uint64_t>(&op.conn->slow_records().compute[op.aux & 0xffffu]);
        if (!compute_.slot_of_answer(answer, &slot, &generation))
            return;
        const double deadline = compute_.started(slot, generation);
        if (deadline > 0.0)
            arm_compute_deadline(slot, generation, deadline);
    }

    // One timeout, one record, one timespec. The record carries which pool
    // slot and which taking of it, and the kernel reads the timespec at
    // submit - so neither may be written again while this timeout is still
    // in the ring. A record is taken here and given back when its
    // completion lands, which is the only moment both are free.
    //
    // #113: sharing one record per pool slot was wrong. A re-arm rewrote
    // the generation in place, and the timeout of a job that had already
    // answered read the number of the job the slot holds now and
    // interrupted that one.
    void arm_compute_deadline(unsigned slot, uint16_t generation, double deadline)
    {
        if (deadline <= 0.0)
            return;
        size_t at = 0;
        while (at < deadlines_.size() && deadlines_[at].busy)
            at++;
        if (at == deadlines_.size()) {
            // The record grows first and the whole of it at once. A raise
            // here leaves nothing half made, because nothing is marked
            // busy until the SQE is in the ring.
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
        // The whole index, not a field of one: a truncated index makes two
        // live timeouts name one record and one timespec.
        io_uring_sqe_set_data64(sqe, arm(owed.op, nullptr, detail::kComputeDeadline,
                                         static_cast<uint32_t>(at)));
        owed.busy = true;
        compute_.name_deadline(slot, generation, reinterpret_cast<uint64_t>(&owed.op));

    }

    // The timeout fired, or the answer came first and the job's own record
    // took it out of the ring. Either way this record is free again.
    void on_compute_deadline(Op &op, const struct io_uring_cqe *completion)
    {
        const size_t at = op.aux;
        if (mrb_unlikely(at >= deadlines_.size()))
            fatal("ring: a compute deadline named a record this process never took");
        Deadline &owed = deadlines_[at];
        owed.busy = false;
        // The record is free, so its address is no longer this job's
        // timeout. Left standing, the next job to take this record would
        // have its own timeout removed by the first job's answer.
        compute_.name_deadline(owed.slot, owed.generation, 0);
        if (completion->res == -ETIME)
            compute_.interrupt(owed.slot, owed.generation);
    }

    // #80: the answer came before the deadline. The timeout leaves the
    // ring, so the record is free again rather than held for the whole of
    // a max_runtime the job never used. Without this the pool grows with
    // the job rate times that runtime, and the records are never reused.
    void drop_compute_deadline(uint64_t timeout_tag)
    {
        if (timeout_tag == 0)
            return;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_timeout_remove(sqe, timeout_tag, 0);
        // Nobody reads the removal itself. Whether it found the timeout or
        // the timeout had already fired, the deadline's own completion is
        // what frees the record.
        io_uring_sqe_set_data64(sqe, 0);
    }

    // The fd leaves through the ring like every other descriptor here.
    void arm_file_close(Conn &c, int descriptor)
    {
        if (descriptor < 0)
            return;
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_close(sqe, descriptor);
        io_uring_sqe_set_data64(sqe, arm(c.op_file_close, &c, detail::kFileClose));
    }

    // The head is spelled; `spell_next_round` is what puts it on the wire, so a connection
    // mid-send is left to on_send's own continuation.
    void file_wake(Conn &c)
    {
        if (!c.sending)
            continue_conn(c);
    }

    // RFC 9110 6.4: one write of a request body into its spill file. The
    // reactor asks on every recv and every round, and the answer is no
    // for every connection that is not taking a large upload.
    //
    // A blocking write(2) on this thread is what this replaces. One write
    // flies per connection: the file has one offset, and the answer
    // carries a connection and a generation with no field for a second
    // body.
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

    // The write landed, or it failed. The application counts the octets,
    // and a run that stopped for this body learns whether it may go on.
    void on_spill_write(Completed done)
    {
        Conn &c = done.conn;
        // A connection that died under the write: the octets were written
        // from this reactor's buffer, so there is nothing to hand back.
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

    // #80: a worker answered. The tag is the connection's, so the same
    // generation guard every other op relies on discards an answer whose
    // connection is already gone - the run died with the slot, and its
    // frame with it.
    //
    // Nothing is resumed here. The run needs a sink and a plan to write
    // its answer into, and this is not a point where either exists; `spell_next_round`
    // is. So this only says the answer arrived, and takes the same door
    // response.file takes.
    void on_compute_task(Op &op, struct io_uring_cqe *completion)
    {
        (void)completion;
        Conn &c = *op.conn;
        const uint32_t aux = op.aux;
        const uint8_t park_gen = static_cast<uint8_t>(aux >> 16);
        const size_t job = static_cast<size_t>(aux & 0xffffu);
        const uint8_t park = static_cast<uint8_t>(job / App::Conn::kJobSlots);
        const uint8_t slot = static_cast<uint8_t>(job % App::Conn::kJobSlots);
        // The pool keeps a job under the address of the record that named
        // it, which is the same value the worker echoed back.
        const uint64_t poll_tag = reinterpret_cast<uint64_t>(&op);
        ComputeAnswer answered;
        const bool have = compute_.take(poll_tag, &answered);
        // #80: the job is over, so its deadline has nothing left to bound.
        drop_compute_deadline(answered.deadline_tag);
        if (!have) {
            // No busy slot answers to this record. That is our own
            // bookkeeping gone wrong, not the application's, and the run
            // still gets a 500 - so it is said rather than swallowed.
            answered.raised = true;
            say_server_error(app_.error_log(),
                             "a compute answer arrived for a job the pool does not hold");
        }
        // A raise inside a worker is the one failure nobody else can see:
        // it happened on another thread, in another VM, and the client only
        // gets a 500. So it goes to the error log whole - class, message,
        // backtrace and which worker - and it goes there even when the
        // connection is gone, because the fault is the application's either
        // way.
        if (answered.raised && have) {
            fault_report(app_.error_log(), mrb_,
                         {answered.exception, answered.step, answered.worker_name,
                          !c.dead && c.peer != nullptr
                              ? std::string_view{reinterpret_cast<const char *>(&c.peer->addr),
                                                 static_cast<size_t>(c.peer->addrlen)}
                              : std::string_view{},
                          static_cast<uint16_t>(answered.over_deadline ? 500 : 503)});
        }
        // A generation that moved means the connection is gone and its run
        // died with it. The answer is still taken, because the slot is the
        // pool's and would otherwise stay busy for the life of the process.
        if (c.dead)
            return;
        // The park was taken again since this job was sent: the answer is a
        // round's that ended, and the round parked there now is not its.
        if (App::park_generation(c.app, park) != park_gen)
            return;
        App::compute_task_answered(c.app, static_cast<int>(park), static_cast<int>(slot), answered);
        if (!c.sending)
            continue_conn(c);
    }

    // ENOENT, EXDEV (RESOLVE_BENEATH), ELOOP (RESOLVE_NO_SYMLINKS), EACCES -
    // One answer for all of them, so probing for a symlink or a traversal
    // cannot be told apart from asking for a name that was never there.
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

    // statx on the opened fd, never by path: size and mtime have to describe
    // the bytes openat2 confined, and a second resolve would not be confined.
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
        // A large file is mapped, not read: the sends walk the mapping and the
        // fd is done with. A failed mmap is not an error - the read path below
        // serves the same bytes, only slower, and `want` is a window whatever
        // the answer here was, so falling through cannot ask for the file.
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

    // A short read is ordinary and resumes; res == 0 before the end is the
    // file shrinking under the Content-Length statx already named, which is a
    // framing lie - refused, not sent.
    void on_file_read(Completed done)
    {
        struct io_uring_cqe *const cqe = done.cqe;
        Conn &c = done.conn;
        c.file_io->reading = false;
        const int fd = c.file_io->fd;
        if (c.dead) {
            c.file_io->fd = -1;
            arm_file_close(c, fd);
            // The connection ended under this read and its close waited for
            // it. Nothing writes that buffer now, so the close may go on.
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
            // Short of the window with nothing left to read: the file shrank under
            // the Content-Length statx already promised. The framing would lie, so
            // the answer is refused rather than sent.
            c.file_io->fd = -1;
            arm_file_close(c, fd);
            app_.file_error(c.app, "the file shrank while it was read");
            file_wake(c);
            return;
        }
        c.file_io->offset += c.file_io->filled;
        // The fd stays open while the file still owes windows; continue_conn
        // arms the next read once the round this one feeds has drained.
        if (c.file_io->offset >= c.file_io->stx_size) {
            c.file_io->fd = -1;
            arm_file_close(c, fd);
        }
        app_.file_ready_now(c.app, c.file_io->filled);
        file_wake(c);
    }

    // SO_MEMINFO through the ring.
    void arm_meminfo(Conn &c)
    {
        struct io_uring_sqe *sqe = sqe_or_submit();
        io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_GETSOCKOPT, static_cast<int>(c.fd), SOL_SOCKET,
                               SO_MEMINFO, c.meminfo, sizeof(c.meminfo));
        sqe->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(sqe, arm(c.op_meminfo, &c, detail::kMeminfo));
    }

    // The peer's address, through liburing's own prep - the last argument
    // is what picks the peer over this socket's own name. Only when
    // someone is logging.
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
    // The peer's raw sockaddr for the log; "-" and one line if the kernel
    // has no such cmd.
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

    // The round's byte bound, from the socket's own books.
    void on_meminfo(Conn &c, struct io_uring_cqe *completion)
    {
        // A send completes, this is armed, and a recv error in the same
        // batch closes the connection: the round below would be spelled
        // onto a socket whose close is already submitted.
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
        // Nothing went out this round, so the window lent to the last one is
        // off the wire and the buffer is free. This is the only point where the
        // next window may be read - doing it on the round that just lent the
        // buffer out overwrites the bytes still being sent.
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
        // Nothing owed and nothing on the wire - the one point where handing the
        // file read buffer back cannot pull it out from under anybody.
        if ((c.file_io == nullptr || !c.file_io->reading) && !app_.pending(c.app)) {
            App::file_release(c.app);
        }
    }
    // One completion. The SQE carried the address of the record that armed
    // it, and that record names the connection - there is no table, no slot
    // and no generation to decode.
    void handle(struct io_uring_cqe *completion)
    {
        const uint64_t user_data = io_uring_cqe_get_data64(completion);
        // A submission nobody reads carries nothing. The worker's own
        // send is one of those.
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
        // The reference goes back however this ends - the fall through, a
        // ConnFailed, or a raise out of the ConnFailed handler itself,
        // which no later clause of the same try would catch.
        const Released give_back{this, &op, completion};
        // The try is here and not around a dispatch() of its own. This is
        // the hottest path in the reactor, and a separate function takes
        // on_send back out of line: measured, that cost 5%.
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
                // #80: a job that ran past its max_runtime. The timeout also
                // completes when it is cancelled or when the job answered
                // first; the pool reads the job number and leaves such a worker
                // alone.
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

    // The one place a ConnFailed lands, whoever threw it.
    void connection_failed(Conn &c, const ConnFailed &field)
    {
        say_connection_failed(field, c);
        begin_close(c);
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
            {
                // A raise out of handle used to leave this completion in
                // the queue. A caller that rescues and ticks again then
                // dispatched the same record a second time, and the second
                // release names a block the first one freed.
                const Seen done{&ring_, cqe};
                handle(cqe);
            }
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
            // Taken first, so a raise out of arm_recv cannot leave stale
            // entries for the next tick, and so an arm_recv that closes a
            // connection cannot walk the vector it is appending to.
            std::vector<Rearm> owed;
            owed.swap(rearm_);
            // Every reference in the list goes back, including those behind
            // an arm_recv that raised on an SQ it could not grow.
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
            // #113: the live list. begin_close only marks, and no accept
            // runs inside this sweep, so the next link is read before the
            // body in case the body ends this connection.
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
                        // RFC 6455 7.1.1: a WebSocket hears a Close frame before the
                        // socket goes. The send carries it and closes behind it.
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
    // #113: every connection that exists, newest first. There is no table
    // to walk, so this is what the idle sweep and the drain read.
    Conn *live_head_ = nullptr;
    // The operations that belong to the process rather than to a peer: the
    // listeners, the two log streams, the stop signal, the setup chain.
    // Their `conn` is null, so release() counts nothing for them - they
    // live as long as the ring does. The listener and stage arrays are
    // configuration, sized by kMaxListeners, and not a table of peers.
    Op op_stop_;
    Op op_poll_remove_;
    Op op_unlink_;
    // One record per log send that can fly beside another: the access
    // line, the error record's fixed head, and the error record's text.
    enum : unsigned { kLogAccess = 0, kLogErrorHead = 1, kLogErrorBody = 2, kLogRecords = 3 };
    Op op_log_[kLogRecords];
    Op op_accept_[kMaxListeners];
    Op op_listener_close_[kMaxListeners];
    // One per (listener, stage): the chain submits its stages together, so
    // each needs an address of its own to say which one refused.
    Op op_setup_[kMaxListeners][detail::kStReuseport + 1];
    std::vector<Rearm> rearm_;
    // One per timeout in the ring, not one per worker slot: the record,
    // the timespec the kernel reads at submit, and which job it bounds.
    // A deque, because the kernel holds the address of both the record and
    // the timespec and a vector moves its elements when it grows.
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
    // A listener whose last accept met a full descriptor table. It is armed
    // again by the next conn_free, and not before.
    bool accept_stalled_[kMaxListeners] = {};
    bool table_full_said_ = false;
    // A descriptor came free, so a stalled listener may be armed again.
    // The note is made where a raise cannot go and read where one can.
    bool accept_retry_owed_ = false;
    static constexpr unsigned kSaidMax = 24;
    const char *said_[kSaidMax] = {};
    unsigned said_count_ = 0;
    int bound_port_[kMaxListeners] = {};
    std::vector<std::string> unix_paths_;
    uint32_t nlisteners_ = 0;
    bool listeners_closed_ = false;
    // The rings this one hands its accepted peers to, and whose turn it
    // is. Round robin: the kernel's own choice is what a shared listener
    // already got wrong, so this ring makes the choice itself.
    const int *worker_ring_fds_ = nullptr;
    uint32_t nworkers_ = 0;
    uint32_t next_worker_ = 0;
    bool draining_ = false;
    int64_t drain_deadline_ = 0;
    uint32_t live_ = 0;
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
    // Which connection owes a fresh recv, and which tenant of the slot
    // owed it. The generation is half the entry: sqe() submits mid-batch
    // when the queue fills, so a close and a new accept for one slot can
    // both be handled inside a single batch, and a second multishot recv
    // on one socket delivers its bytes outside the parser's order.
    // Which connection owes a fresh recv. The connection itself, because
    // there is no slot to name and no tenant of one to tell apart: the
    // address is the connection for as long as it exists.
};

} // namespace webmachine

#endif
