// The bodies of what ring_setup.hpp declares: the two limit raises, the
// descriptor budget, the completion tags and the setup stage names.
#include "ring_setup.hpp"

namespace webmachine
{
void raise_memlock()
{
    struct rlimit rl {
    };
    if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        return;
    if (rl.rlim_cur == rl.rlim_max)
        return;
    struct rlimit want {
        rl.rlim_max, rl.rlim_max
    };
    (void)::setrlimit(RLIMIT_MEMLOCK, &want);
}

uint32_t derive_max_conns(FdBudget block)
{
    const uint64_t nofile_limit = block.nofile_limit;
    const uint32_t extra_slots = block.extra_slots;
    const uint32_t rings = block.rings != 0 ? block.rings : 1;
    // Three quarters of the limit go to the rings, and they share it.
    // The last quarter stays for every descriptor this process opens
    // outside a ring table: its own few, a request body in a file, a log,
    // whatever an application opens. A ring that took the whole limit
    // left nothing for them.
    const uint64_t for_rings = (nofile_limit / 4) * 3;
    const uint64_t taken = static_cast<uint64_t>(kMaxListeners) + extra_slots;
    if (for_rings <= taken * rings)
        return 0;
    uint64_t n = for_rings / rings - taken;
    if (n == 0)
        return 0;
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
