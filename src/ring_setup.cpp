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
uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx)
{
    return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
}

uint64_t watch_tag(uint16_t gen, uint32_t idx, uint8_t slot)
{
    return tag(kWatch, gen, idx) | (static_cast<uint64_t>(slot) << 48);
}

uint8_t watch_slot(uint64_t user_data)
{
    return static_cast<uint8_t>(user_data >> 48);
}

uint64_t compute_deadline_tag(unsigned slot, uint16_t gen)
{
    return tag(kComputeDeadline, gen, static_cast<uint32_t>(slot));
}

uint64_t compute_started_tag(unsigned slot, uint16_t gen)
{
    return tag(kComputeStarted, gen, static_cast<uint32_t>(slot));
}

uint64_t compute_task_tag(uint16_t gen, uint32_t idx, uint8_t park, uint8_t job, uint8_t park_gen)
{
    const uint8_t both = static_cast<uint8_t>((park << 4) | (job & 0x0f));
    const uint32_t word = (idx & 0xffffffu) | (static_cast<uint32_t>(park_gen) << 24);
    return tag(kComputeTask, gen, word) | (static_cast<uint64_t>(both) << 48);
}

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
    }
    return "?";
}
} // namespace detail
} // namespace webmachine
