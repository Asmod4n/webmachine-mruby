// The bodies of what ring_setup.hpp declares: the two limit raises, the
// descriptor budget, the completion tags and the setup stage names.
#include "ring_setup.hpp"

namespace webmachine
{
uint64_t raise_memlock()
{
    struct rlimit rl {
    };
    if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        return 0;
    if (rl.rlim_cur != rl.rlim_max) {
        struct rlimit want {
            rl.rlim_max, rl.rlim_max
        };
        (void)::setrlimit(RLIMIT_MEMLOCK, &want);
        if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
            return 0;
    }
    if (rl.rlim_cur == RLIM_INFINITY)
        return UINT64_MAX;
    return static_cast<uint64_t>(rl.rlim_cur);
}

// How many submission entries each ring of this process gets. The rings
// are locked memory charged to the process, and three quarters of
// RLIMIT_MEMLOCK are theirs to share.
//
// Measured, not reasoned: on a box with 8 MiB of locked memory, two rings
// of 32768 entries come up and the third answers ENOMEM. One such ring is
// its submission queue (32768 * 64) plus its completion queue (65536 *
// 16), which is 3 MiB, so two fit in 8 MiB and three do not. The server
// opens one ring per answering thread plus one that accepts, so at
// --threads=3 it wants four and gets two.
//
// One entry therefore costs its own submission slot plus its two
// completion slots - the completion queue holds twice the submission
// count unless asked otherwise - and both sizes come from io_uring's own
// structures rather than from a number of ours.
//
// kSqEntriesMax is the kernel's own ceiling, written in its C code. It has
// nothing to do with the limit above and bounds the answer however large
// an operator makes that limit.
//
// --workers=N shares the same way. A child is its own process, but the
// kernel charges a ring's memory to the user - io_uring_register(2) says
// as much of RLIMIT_NOFILE, and io_account_mem charges RLIMIT_MEMLOCK
// against the same user struct. Measured: three children of 32768
// entries want 9 MiB where the user has 8, and none of them comes up.
unsigned derive_sq_entries(uint64_t memlock_limit, uint32_t rings)
{
    constexpr uint64_t per_entry = sizeof(struct io_uring_sqe) + 2 * sizeof(struct io_uring_cqe);
    if (rings == 0)
        rings = 1;
    if (memlock_limit == UINT64_MAX)
        return kSqEntriesMax;
    const uint64_t fit = (memlock_limit / 4) * 3 / rings / per_entry;
    if (fit >= kSqEntriesMax)
        return kSqEntriesMax;
    // A submission queue is a power of two, so the answer is the largest
    // one that fits.
    unsigned answer = 1;
    while (answer * 2u <= fit)
        answer *= 2;
    return answer;
}

uint32_t derive_max_conns(FdBudget block)
{
    const uint64_t nofile_limit = block.nofile_limit;
    const uint32_t extra_slots = block.extra_slots;
    const uint64_t taken =
        static_cast<uint64_t>(kFdReserve) + kBodyFilesMax + kMaxListeners + extra_slots;
    if (nofile_limit <= taken)
        return 0;
    uint64_t n = nofile_limit - taken;
    if (n + kMaxListeners + extra_slots > kFixedTableKernelMax) {
        n = kFixedTableKernelMax - kMaxListeners - extra_slots;
    }
    return static_cast<uint32_t>(n);
}

uint64_t raise_nofile()
{
    struct rlimit rl {
    };
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return 0;
#ifdef IO_URING_FD_CEILING
    rlim_t target = static_cast<rlim_t>(IO_URING_FD_CEILING - 1);
    if (target > rl.rlim_max)
        target = rl.rlim_max;
    if (rl.rlim_cur != target) {
        struct rlimit want {
            target, rl.rlim_max
        };
        (void)::setrlimit(RLIMIT_NOFILE, &want);
        if (::getrlimit(RLIMIT_NOFILE, &rl) != 0)
            return 0;
    }
    const uint64_t cur = static_cast<uint64_t>(rl.rlim_cur);
    return cur < IO_URING_FD_CEILING ? cur : IO_URING_FD_CEILING - 1;
#else
    rlim_t target = rl.rlim_max;
    if (target == RLIM_INFINITY) {
        uint64_t nr_open = 1u << 20;
        if (std::FILE *facts = std::fopen("/proc/sys/fs/nr_open", "re")) {
            unsigned long long value = 0;
            if (std::fscanf(facts, "%llu", &value) == 1 && value > 0)
                nr_open = value;
            std::fclose(facts);
        }
        target = static_cast<rlim_t>(nr_open);
    }
    if (rl.rlim_cur < target) {
        struct rlimit want {
            target, rl.rlim_max
        };
        (void)::setrlimit(RLIMIT_NOFILE, &want);
        if (::getrlimit(RLIMIT_NOFILE, &rl) != 0)
            return 0;
    }
    return static_cast<uint64_t>(rl.rlim_cur);
#endif
}

namespace detail
{
const char *stage_name(uint32_t conn)
{
    switch (conn) {
        case kStSocket:
            return "socket";
        case kStSockopt:
            return "setsockopt";
        case kStBind:
            return "bind";
        case kStListen:
            return "listen";
        case kStName:
            return "getsockname";
        case kStUnlink:
            return "unlink";
        case kStReuseport:
            return "setsockopt SO_REUSEPORT";
    }
    return "?";
}
} // namespace detail
} // namespace webmachine
