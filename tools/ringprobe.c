/* What the reactor does at start, and nothing else: make the ring,
 * register the file table, set up the provided buffer ring. Each step
 * says what the kernel said, so a refusal names the step and the size
 * rather than the whole server.
 *
 *   cc -O1 -o ringprobe tools/ringprobe.c -luring
 *   ./ringprobe [entries] [table_slots] [bufs] [rings]
 *
 * table_slots of 0 means "what the server asks for today", which is
 * RLIMIT_NOFILE less the reserve. Run it as the user the server runs
 * as: root does not answer for anybody else, because RLIMIT_MEMLOCK is
 * not enforced under CAP_IPC_LOCK.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <liburing.h>

static void say_limit(const char *name, int what)
{
    struct rlimit rl;
    if (getrlimit(what, &rl) != 0) {
        printf("%s: getrlimit failed\n", name);
        return;
    }
    printf("%s: soft=%llu hard=%llu\n", name,
           (unsigned long long) rl.rlim_cur, (unsigned long long) rl.rlim_max);
}

static void raise_soft_to_hard(int what)
{
    struct rlimit rl;
    if (getrlimit(what, &rl) != 0)
        return;
    rl.rlim_cur = rl.rlim_max;
    (void) setrlimit(what, &rl);
}

int main(int argc, char **argv)
{
    unsigned entries = argc > 1 ? (unsigned) strtoul(argv[1], NULL, 10) : 32768;
    unsigned slots   = argc > 2 ? (unsigned) strtoul(argv[2], NULL, 10) : 0;
    unsigned bufs    = argc > 3 ? (unsigned) strtoul(argv[3], NULL, 10) : 2048;
    int      rings   = argc > 4 ? atoi(argv[4]) : 1;

    raise_soft_to_hard(RLIMIT_MEMLOCK);
    raise_soft_to_hard(RLIMIT_NOFILE);
    say_limit("memlock", RLIMIT_MEMLOCK);
    say_limit("nofile ", RLIMIT_NOFILE);

    if (slots == 0) {
        struct rlimit rl;
        getrlimit(RLIMIT_NOFILE, &rl);
        unsigned long long n = (unsigned long long) rl.rlim_cur;
        slots = n > 1168 ? (unsigned) (n - 1168) : 1;
        if (slots > (1u << 20))
            slots = 1u << 20;
    }
    printf("asking: entries=%u table_slots=%u bufs=%u rings=%d\n", entries, slots, bufs, rings);

    for (int r = 0; r < rings; r++) {
        struct io_uring ring;
        struct io_uring_params p;
        memset(&p, 0, sizeof(p));
        p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
                  IORING_SETUP_COOP_TASKRUN;
        int rc = io_uring_queue_init_params(entries, &ring, &p);
        if (rc != 0) {
            printf("ring %d: queue_init(%u): %s\n", r, entries, strerror(-rc));
            return 1;
        }
        printf("ring %d: queue_init ok (sq=%u cq=%u)\n", r, p.sq_entries, p.cq_entries);

        rc = io_uring_register_files_sparse(&ring, slots + 16);
        if (rc != 0) {
            printf("ring %d: register_files_sparse(%u): %s\n", r, slots + 16, strerror(-rc));
            return 1;
        }
        printf("ring %d: register_files_sparse(%u) ok\n", r, slots + 16);

        rc = io_uring_register_file_alloc_range(&ring, 0, slots);
        if (rc != 0) {
            printf("ring %d: register_file_alloc_range: %s\n", r, strerror(-rc));
            return 1;
        }

        void *pool = mmap(NULL, (size_t) bufs * 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pool == MAP_FAILED) {
            printf("ring %d: mmap pool: %s\n", r, strerror(errno));
            return 1;
        }
        int bre = 0;
        struct io_uring_buf_ring *br = io_uring_setup_buf_ring(&ring, bufs, 1, 0, &bre);
        if (br == NULL) {
            printf("ring %d: setup_buf_ring(%u): %s\n", r, bufs, strerror(-bre));
            return 1;
        }
        printf("ring %d: setup_buf_ring(%u) ok\n", r, bufs);
    }
    printf("all %d ring(s) up\n", rings);
    return 0;
}
