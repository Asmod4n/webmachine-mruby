// What a value costs when it crosses a thread, and what a completion
// costs when it does not.
//
// Three arms, all in one process, all on this host:
//
//   futex   two threads hand a word back and forth and BLOCK between
//           handovers. Every handover is a real context switch: a
//           FUTEX_WAKE, a scheduler decision, and the other thread
//           returning from FUTEX_WAIT.
//   spin    the same handover with neither thread blocking. Nothing
//           reaches the scheduler, so what is left is one cache line
//           moving from one core to the other.
//   ring    io_uring_for_each_cqe over a ring that carries multishot
//           accept and multishot recv at the same time. The number is
//           per completion taken out of the queue, and taking one is
//           reading shared memory: no syscall, no switch.
//
// The ring arm needs traffic, so a peer thread opens unix sockets and
// writes to them. That thread is the load generator, not the subject.
//
//   switch_bench [--seconds S] [--peers N] [--loaders N] [--bufs N]
//                [--sock PATH]
//
// One file, one library. To carry it to another host, copy this file
// and run:
//
//     g++ -O2 -march=native -std=c++20 switch.cpp -luring -o switch_bench
//     ./switch_bench --seconds 2 --peers 24 --loaders 3
//
// The ENOBUFS question needs a buffer group that runs dry, so ask for a
// small one and read the last line:
//
//     ./switch_bench --seconds 2 --peers 24 --loaders 3 --bufs 16
//
// Record `uname -r` and the liburing version beside whatever it says.
// On 6.18.44-fc every ENOBUFS ended the multishot; the kernel fixed
// that in 7.1, and no host here runs 7.1 or later.

#include <liburing.h>
#include <linux/futex.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include <sched.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <new>
#include <string>
#include <thread>
#include <vector>

namespace {

[[noreturn]] void die(const char *what)
{
    std::perror(what);
    std::exit(1);
}

uint64_t now_ns()
{
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

// What one pair of clock reads costs, so the ring arm can name it and
// take it off the batch it wraps.
double clock_pair_ns()
{
    const int rounds = 200000;
    const uint64_t began = now_ns();
    for (int i = 0; i < rounds; i++) {
        const uint64_t a = now_ns();
        const uint64_t b = now_ns();
        if (b < a)
            std::abort();
    }
    const uint64_t ended = now_ns();
    // Each round holds two pairs: the two reads of the round, and the
    // outer loop's share. Two reads is one pair.
    return static_cast<double>(ended - began) / rounds / 2.0;
}

// Which cpu a thread ended on, and whether the two are siblings of one
// core. This decides the handover arms more than anything else: two
// threads on one core's SMT siblings share a cache level that two
// cores do not, and two sockets share less still. The run reads it off
// itself rather than trusting whoever writes the row.
std::string read_line_of(const char *path)
{
    std::FILE *f = std::fopen(path, "r");
    if (f == nullptr)
        return std::string();
    char line[64] = {0};
    if (std::fgets(line, sizeof line, f) == nullptr)
        line[0] = 0;
    std::fclose(f);
    std::string out(line);
    while (!out.empty() && (out.back() == '\n' || out.back() == ' '))
        out.pop_back();
    return out;
}

// A hybrid cpu answers here: a performance core carries a higher
// capacity and a higher top frequency than an efficiency core, and a
// handover between the two kinds is a different measurement from a
// handover between two of one kind.
std::string kind_of(int cpu)
{
    char path[160];
    std::snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
    const std::string capacity = read_line_of(path);
    std::snprintf(path, sizeof path,
                  "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
    const std::string top = read_line_of(path);
    if (capacity.empty() && top.empty())
        return std::string("?");
    std::string out;
    if (!capacity.empty())
        out += "cap" + capacity;
    if (!top.empty())
        out += (out.empty() ? "" : "/") + top + "kHz";
    return out;
}

std::string siblings_of(int cpu)
{
    char path[160];
    std::snprintf(path, sizeof path,
                  "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
    const std::string out = read_line_of(path);
    return out.empty() ? std::string("?") : out;
}

// One word per cache line, so the two threads do not share one by
// accident. The value is the ball: A writes 1, B writes 2, and so on.
struct alignas(std::hardware_destructive_interference_size) Cell {
    std::atomic<uint32_t> word{0};
};

long futex_wait(std::atomic<uint32_t> *word, uint32_t expect)
{
    return syscall(SYS_futex, word, FUTEX_WAIT_PRIVATE, expect, nullptr, nullptr, 0);
}

long futex_wake(std::atomic<uint32_t> *word)
{
    return syscall(SYS_futex, word, FUTEX_WAKE_PRIVATE, 1, nullptr, nullptr, 0);
}

// A handover that blocks. The count is round trips; a round trip is two
// handovers and therefore two context switches.
struct Handovers {
    uint64_t trips = 0;
    uint64_t ns = 0;
    int cpu_here = -1;
    int cpu_peer = -1;
};

Handovers futex_round_trips(double seconds)
{
    Cell a;
    Cell b;
    std::atomic<bool> stop{false};
    Handovers out;

    std::thread peer([&] {
        uint32_t seen = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            while (a.word.load(std::memory_order_acquire) == seen) {
                futex_wait(&a.word, seen);
                if (stop.load(std::memory_order_relaxed))
                    return;
            }
            seen = a.word.load(std::memory_order_acquire);
            b.word.store(seen, std::memory_order_release);
            futex_wake(&b.word);
            out.cpu_peer = sched_getcpu();
        }
    });

    const uint64_t began = now_ns();
    const uint64_t until = began + static_cast<uint64_t>(seconds * 1e9);
    uint32_t ball = 0;
    uint32_t seen = 0;
    while (now_ns() < until) {
        for (int i = 0; i < 64; i++) {
            ball++;
            a.word.store(ball, std::memory_order_release);
            futex_wake(&a.word);
            while (b.word.load(std::memory_order_acquire) == seen) {
                futex_wait(&b.word, seen);
            }
            seen = b.word.load(std::memory_order_acquire);
            out.trips++;
        }
    }
    out.ns = now_ns() - began;
    out.cpu_here = sched_getcpu();
    stop.store(true, std::memory_order_relaxed);
    a.word.fetch_add(1, std::memory_order_release);
    futex_wake(&a.word);
    peer.join();
    return out;
}

// The same handover with nobody blocking. The scheduler never hears of
// it, so this is the cache line and nothing else.
Handovers spin_round_trips(double seconds)
{
    Cell a;
    Cell b;
    std::atomic<bool> stop{false};
    Handovers out;

    std::thread peer([&] {
        uint32_t seen = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            uint32_t got = a.word.load(std::memory_order_acquire);
            while (got == seen) {
                if (stop.load(std::memory_order_relaxed))
                    return;
                got = a.word.load(std::memory_order_acquire);
            }
            seen = got;
            b.word.store(seen, std::memory_order_release);
            out.cpu_peer = sched_getcpu();
        }
    });

    const uint64_t began = now_ns();
    const uint64_t until = began + static_cast<uint64_t>(seconds * 1e9);
    uint32_t ball = 0;
    uint32_t seen = 0;
    while (now_ns() < until) {
        for (int i = 0; i < 1024; i++) {
            ball++;
            a.word.store(ball, std::memory_order_release);
            while (b.word.load(std::memory_order_acquire) == seen) {
            }
            seen = b.word.load(std::memory_order_acquire);
            out.trips++;
        }
    }
    out.ns = now_ns() - began;
    out.cpu_here = sched_getcpu();
    stop.store(true, std::memory_order_relaxed);
    peer.join();
    return out;
}

// ---- the ring arm ----

constexpr uint64_t kAcceptTag = 1;
constexpr uint64_t kRecvTag = 2;
constexpr unsigned kBufGroup = 7;
// The tag is the low byte and the connection's index is the rest: a
// multishot recv ends when the buffer group runs dry, and the arm that
// follows needs to know which connection it belongs to.
constexpr unsigned kTagBits = 8;

uint64_t recv_tag(int index)
{
    return kRecvTag | (static_cast<uint64_t>(index) << kTagBits);
}

int tag_index(uint64_t tag)
{
    return static_cast<int>(tag >> kTagBits);
}

struct RingArm {
    uint64_t cqes = 0;
    uint64_t batches = 0;
    uint64_t harvest_ns = 0;
    uint64_t enters = 0;
    uint64_t accepts = 0;
    uint64_t recvs = 0;
    uint64_t bytes = 0;
    uint64_t rearms = 0;
    // ENOBUFS is the question this counts: does the kernel keep the
    // multishot armed when the buffer group runs dry?
    uint64_t enobufs = 0;
    uint64_t enobufs_more = 0;
};

int listen_unix(const char *path)
{
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        die("socket");
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    unlink(path);
    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof addr) < 0)
        die("bind");
    if (listen(fd, 512) < 0)
        die("listen");
    return fd;
}

// The load generator. It opens peers over the run rather than all at
// once, so multishot accept keeps delivering beside multishot recv.
void peer_thread(const char *path, unsigned peers, double seconds, std::atomic<bool> &stop)
{
    std::vector<int> socks;
    socks.reserve(peers);
    const uint64_t until = now_ns() + static_cast<uint64_t>(seconds * 1e9);
    const uint64_t open_every = static_cast<uint64_t>(seconds * 1e9) / (peers + 1);
    uint64_t open_next = now_ns();
    char msg[64];
    std::memset(msg, 'x', sizeof msg);

    while (!stop.load(std::memory_order_relaxed) && now_ns() < until) {
        if (socks.size() < peers && now_ns() >= open_next) {
            const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd >= 0) {
                struct sockaddr_un addr{};
                addr.sun_family = AF_UNIX;
                std::snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
                if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof addr) == 0) {
                    socks.push_back(fd);
                } else {
                    close(fd);
                }
            }
            open_next = now_ns() + open_every;
        }
        for (size_t i = 0; i < socks.size(); i++) {
            if (send(socks[i], msg, sizeof msg, MSG_NOSIGNAL | MSG_DONTWAIT) < 0
                && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                close(socks[i]);
                socks[i] = socks.back();
                socks.pop_back();
                break;
            }
        }
    }
    for (const int fd : socks)
        close(fd);
}

void arm_recv(struct io_uring *ring, int index)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe == nullptr)
        die("no sqe for recv");
    io_uring_prep_recv_multishot(sqe, index, nullptr, 0, 0);
    sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
    sqe->buf_group = kBufGroup;
    io_uring_sqe_set_data64(sqe, recv_tag(index));
}

void arm_accept(struct io_uring *ring, int listen_fd)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe == nullptr)
        die("no sqe for accept");
    io_uring_prep_multishot_accept_direct(sqe, listen_fd, nullptr, nullptr, 0);
    io_uring_sqe_set_data64(sqe, kAcceptTag);
}

RingArm ring_harvest(const char *path, unsigned peers, unsigned loaders, unsigned nbufs,
                     double seconds, double clock_ns)
{
    RingArm out;
    const int listen_fd = listen_unix(path);

    struct io_uring ring{};
    struct io_uring_params params{};
    // The reactor's own flags (src/ring.hpp), so the number prices the
    // submission model the server runs.
    params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN
                   | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_CQSIZE;
    params.cq_entries = 16384;
    if (io_uring_queue_init_params(4096, &ring, &params) < 0)
        die("io_uring_queue_init_params");
    if (io_uring_register_files_sparse(&ring, 1024) < 0)
        die("register_files_sparse");

    const unsigned bufsize = 1024;
    int err = 0;
    struct io_uring_buf_ring *br = io_uring_setup_buf_ring(&ring, nbufs, kBufGroup, 0, &err);
    if (br == nullptr) {
        errno = -err;
        die("setup_buf_ring");
    }
    std::vector<char> pool(static_cast<size_t>(nbufs) * bufsize);
    for (unsigned i = 0; i < nbufs; i++) {
        io_uring_buf_ring_add(br, &pool[static_cast<size_t>(i) * bufsize], bufsize, i,
                              io_uring_buf_ring_mask(nbufs), static_cast<int>(i));
    }
    io_uring_buf_ring_advance(br, static_cast<int>(nbufs));

    arm_accept(&ring, listen_fd);

    std::atomic<bool> stop{false};
    std::vector<std::thread> load;
    load.reserve(loaders);
    for (unsigned i = 0; i < loaders; i++) {
        load.emplace_back(peer_thread, path, peers / loaders, seconds, std::ref(stop));
    }

    const uint64_t until = now_ns() + static_cast<uint64_t>(seconds * 1e9);
    while (now_ns() < until) {
        struct __kernel_timespec wait{};
        wait.tv_nsec = 50 * 1000 * 1000;
        struct io_uring_cqe *first = nullptr;
        io_uring_submit_and_wait_timeout(&ring, &first, 1, &wait, nullptr);
        out.enters++;

        const uint64_t began = now_ns();
        unsigned head = 0;
        unsigned taken = 0;
        struct io_uring_cqe *cqe = nullptr;
        io_uring_for_each_cqe(&ring, head, cqe)
        {
            taken++;
            const uint64_t tag = io_uring_cqe_get_data64(cqe);
            if ((tag & ((1u << kTagBits) - 1)) == kAcceptTag) {
                if (cqe->res >= 0) {
                    out.accepts++;
                    arm_recv(&ring, cqe->res);
                }
                if ((cqe->flags & IORING_CQE_F_MORE) == 0)
                    arm_accept(&ring, listen_fd);
            } else {
                if (cqe->res > 0) {
                    out.recvs++;
                    out.bytes += static_cast<uint64_t>(cqe->res);
                } else if (cqe->res == -ENOBUFS) {
                    out.enobufs++;
                    if ((cqe->flags & IORING_CQE_F_MORE) != 0)
                        out.enobufs_more++;
                }
                if ((cqe->flags & IORING_CQE_F_BUFFER) != 0) {
                    const unsigned bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                    io_uring_buf_ring_add(br, &pool[static_cast<size_t>(bid) * bufsize], bufsize,
                                          bid, io_uring_buf_ring_mask(nbufs), 0);
                    io_uring_buf_ring_advance(br, 1);
                }
                // A multishot recv ends on ENOBUFS and on an error. Arm
                // it again, or the peer writes into a socket nobody
                // reads and the run stops rather than measures.
                if ((cqe->flags & IORING_CQE_F_MORE) == 0 && cqe->res != 0) {
                    out.rearms++;
                    arm_recv(&ring, tag_index(tag));
                }
            }
        }
        io_uring_cq_advance(&ring, taken);
        const uint64_t ended = now_ns();
        if (taken > 0) {
            out.cqes += taken;
            out.batches++;
            out.harvest_ns += ended - began;
        }
    }

    stop.store(true, std::memory_order_relaxed);
    for (auto &one : load)
        one.join();
    io_uring_queue_exit(&ring);
    close(listen_fd);
    unlink(path);
    (void)clock_ns;
    return out;
}

// Where a handover arm ran, so the number can be read. This is where
// the two threads were last seen, not where they stayed: nothing is
// pinned here, and the scheduler may move a thread mid-run.
void print_where(const char *arm, const Handovers &h)
{
    std::printf("%s:  last on cpu %d and cpu %d (siblings of %d: %s; %d is %s, %d is %s)\n", arm,
                h.cpu_here, h.cpu_peer, h.cpu_here, siblings_of(h.cpu_here).c_str(), h.cpu_here,
                kind_of(h.cpu_here).c_str(), h.cpu_peer, kind_of(h.cpu_peer).c_str());
}

} // namespace

int main(int argc, char **argv)
{
    double seconds = 3.0;
    unsigned peers = 32;
    unsigned loaders = 1;
    unsigned nbufs = 4096;
    const char *path = "/tmp/switch_bench.sock";
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = std::atof(argv[++i]);
        } else if (std::strcmp(argv[i], "--peers") == 0 && i + 1 < argc) {
            peers = static_cast<unsigned>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--loaders") == 0 && i + 1 < argc) {
            loaders = static_cast<unsigned>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--bufs") == 0 && i + 1 < argc) {
            nbufs = static_cast<unsigned>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--sock") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 2;
        }
    }

    std::printf("host:  %ld cpus online\n", sysconf(_SC_NPROCESSORS_ONLN));
    const double clock_ns = clock_pair_ns();
    std::printf("clock: one pair of CLOCK_MONOTONIC reads = %.1f ns\n", clock_ns);

    const Handovers futex = futex_round_trips(seconds);
    const uint64_t futex_trips = futex.trips;
    const double futex_ns = static_cast<double>(futex.ns) / static_cast<double>(futex.trips);
    std::printf("futex: %.1f ns per round trip, %.1f ns per handover (blocks: two switches "
                "per round trip), %llu round trips\n",
                futex_ns, futex_ns / 2.0, static_cast<unsigned long long>(futex_trips));
    print_where("futex", futex);

    const Handovers spin = spin_round_trips(seconds);
    const uint64_t spin_trips = spin.trips;
    const double spin_ns = static_cast<double>(spin.ns) / static_cast<double>(spin.trips);
    std::printf("spin:  %.1f ns per round trip, %.1f ns per handover (never blocks: one cache "
                "line), %llu round trips\n",
                spin_ns, spin_ns / 2.0, static_cast<unsigned long long>(spin_trips));
    print_where("spin ", spin);

    if (loaders == 0 || peers / loaders == 0) {
        std::fprintf(stderr, "--peers must be at least --loaders\n");
        return 2;
    }
    const RingArm r = ring_harvest(path, peers, loaders, nbufs, seconds, clock_ns);
    if (r.cqes == 0) {
        std::fprintf(stderr, "ring: no completions - the peer thread sent nothing\n");
        return 1;
    }
    const double per_cqe = static_cast<double>(r.harvest_ns) / static_cast<double>(r.cqes);
    const double per_batch = static_cast<double>(r.cqes) / static_cast<double>(r.batches);
    const double clock_share = clock_ns / per_batch;
    std::printf("ring:  %.1f ns per cqe raw, %.1f ns after the clock pair (%.1f ns over %.1f "
                "cqes per batch)\n",
                per_cqe, per_cqe - clock_share, clock_ns, per_batch);
    std::printf("ring:  %llu cqes in %llu batches, %llu enters, %llu accepts, %llu recvs, "
                "%llu bytes, %llu recv rearms, %.2f cqes per enter\n",
                static_cast<unsigned long long>(r.cqes),
                static_cast<unsigned long long>(r.batches),
                static_cast<unsigned long long>(r.enters),
                static_cast<unsigned long long>(r.accepts),
                static_cast<unsigned long long>(r.recvs),
                static_cast<unsigned long long>(r.bytes),
                static_cast<unsigned long long>(r.rearms),
                static_cast<double>(r.cqes) / static_cast<double>(r.enters));
    std::printf("ring:  %llu enobufs completions, %llu of them kept the multishot armed "
                "(IORING_CQE_F_MORE)\n",
                static_cast<unsigned long long>(r.enobufs),
                static_cast<unsigned long long>(r.enobufs_more));
    return 0;
}
