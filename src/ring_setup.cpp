#include "ring_setup.hpp"

namespace webmachine
{
uint64_t raise_memlock(mrb_state *mrb)
{
    struct rlimit rl {
    };
    if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        raise_errno(mrb, "getrlimit(RLIMIT_MEMLOCK)", errno);
    if (rl.rlim_cur != rl.rlim_max) {
        struct rlimit want {
            rl.rlim_max, rl.rlim_max
        };
        if (::setrlimit(RLIMIT_MEMLOCK, &want) != 0)
            raise_errno(mrb, "setrlimit(RLIMIT_MEMLOCK) to the hard limit", errno);
        if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
            raise_errno(mrb, "getrlimit(RLIMIT_MEMLOCK) after the raise", errno);
    }
    if (rl.rlim_cur == RLIM_INFINITY)
        return UINT64_MAX;
    return static_cast<uint64_t>(rl.rlim_cur);
}

// The kernel charges a ring's memory to the user rather than to the
// process, so every ring this server opens shares one RLIMIT_MEMLOCK:
// threads + 1 for --threads.
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
    // A submission queue is a power of two.
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

uint64_t raise_nofile(mrb_state *mrb)
{
    struct rlimit rl {
    };
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0)
        raise_errno(mrb, "getrlimit(RLIMIT_NOFILE)", errno);
    rlim_t target = rl.rlim_max;
    if (target == RLIM_INFINITY) {
        uint64_t nr_open = 1u << 20;
        if (std::FILE *facts = std::fopen("/proc/sys/fs/nr_open", "re")) {
            unsigned long long value = 0;
            const int fields = std::fscanf(facts, "%llu", &value);
            const int closed = std::fclose(facts);
            if (fields != 1 || value == 0)
                mrb_raise(mrb, E_WM_ERROR(mrb), "/proc/sys/fs/nr_open holds no number");
            if (closed != 0)
                raise_errno(mrb, "fclose /proc/sys/fs/nr_open", errno);
            nr_open = value;
        } else if (errno != ENOENT) {
            // No procfs at all is a container that hides it, and the
            // default above answers. Any other errno is a real refusal.
            raise_errno(mrb, "open /proc/sys/fs/nr_open", errno);
        }
        target = static_cast<rlim_t>(nr_open);
    }
    if (rl.rlim_cur < target) {
        struct rlimit want {
            target, rl.rlim_max
        };
        if (::setrlimit(RLIMIT_NOFILE, &want) != 0)
            raise_errno(mrb, "setrlimit(RLIMIT_NOFILE) to the hard limit", errno);
        if (::getrlimit(RLIMIT_NOFILE, &rl) != 0)
            raise_errno(mrb, "getrlimit(RLIMIT_NOFILE) after the raise", errno);
    }
    return static_cast<uint64_t>(rl.rlim_cur);
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
