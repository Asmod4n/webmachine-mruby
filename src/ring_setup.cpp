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
    }
    return "?";
}
} // namespace detail
// The queue, and nothing of the reactor. Halving from `want` is how the
// kernel is asked what fits: the pages are charged to the user, so a
// second server of the same user is in that budget and cannot be in any
// arithmetic here.
void boot_queue_up(mrb_state *mrb, BootQueue &queue, unsigned want)
{
    if (queue.up)
        mrb_raise(mrb, E_WM_ERROR(mrb), "the queue is up already");
    constexpr unsigned kSqFloor = 1024;
    constexpr unsigned kSetupFlags =
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    const uint64_t memlock = raise_memlock(mrb);
    const unsigned floor = want < kSqFloor ? want : kSqFloor;
    struct io_uring_params p {
    };
    int rc = 0;
    for (queue.entries = want;; queue.entries /= 2) {
        p = io_uring_params{};
        p.flags = kSetupFlags;
        rc = io_uring_queue_init_params(queue.entries, &queue.ring, &p);
        if (rc == 0) {
            queue.entries = p.sq_entries;
            break;
        }
        if (queue.entries <= floor) {
            mrb_raisef(mrb, E_WM_ERROR(mrb),
                       "io_uring_queue_init(%d): %s. RLIMIT_MEMLOCK is %i, and the kernel "
                       "charges a ring's pages to the user rather than to this process",
                       static_cast<int>(queue.entries), std::strerror(-rc),
                       static_cast<mrb_int>(memlock));
        }
    }
    // A kernel without register_ring_fd answers -EINVAL, and that is no
    // reason not to start.
    rc = io_uring_register_ring_fd(&queue.ring);
    if (rc < 0 && rc != -EINVAL) {
        io_uring_queue_exit(&queue.ring);
        mrb_raisef(mrb, E_WM_ERROR(mrb), "register_ring_fd: %s", std::strerror(-rc));
    }
    queue.up = true;
}

void boot_queue_down(BootQueue &queue)
{
    if (!queue.up)
        return;
    io_uring_queue_exit(&queue.ring);
    queue.up = false;
    queue.entries = 0;
}
} // namespace webmachine
