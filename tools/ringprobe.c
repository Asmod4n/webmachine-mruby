/* What the reactor does at start, and nothing else: make the ring,
 * register the file table, set up the provided buffer ring. Each step
 * says what the kernel said, so a refusal names the step and the size
 * rather than the whole server.
 *
 *   cc -O1 -o ringprobe tools/ringprobe.c -luring
 *   ./ringprobe [entries] [table_slots] [bufs] [rings] [threaded]
 *
 * threaded of 1 makes each ring in a thread of its own and registers
 * the ring descriptor, which is what the server does with --threads.
 * IORING_SETUP_SINGLE_ISSUER binds a ring to the task that made it, and
 * a registered ring descriptor is a per-task resource.
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
#include <pthread.h>
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

struct one_ring {
    unsigned entries, slots, bufs;
    int index;
    int failed;
};

/* One ring, made where the caller runs: in main, or in a thread of its
 * own when the run is threaded. */
static void *make_ring(void *arg)
{
    struct one_ring *want = arg;
    struct io_uring ring;
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    int rc = io_uring_queue_init_params(want->entries, &ring, &p);
    if (rc != 0) {
        printf("ring %d: queue_init(%u): %s\n", want->index, want->entries, strerror(-rc));
        want->failed = 1;
        return NULL;
    }
    printf("ring %d: queue_init ok (sq=%u cq=%u)\n", want->index, p.sq_entries, p.cq_entries);

    rc = io_uring_register_ring_fd(&ring);
    if (rc < 0) {
        printf("ring %d: register_ring_fd: %s\n", want->index, strerror(-rc));
        want->failed = 1;
        return NULL;
    }

    rc = io_uring_register_files_sparse(&ring, want->slots + 16);
    if (rc != 0) {
        printf("ring %d: register_files_sparse(%u): %s\n", want->index, want->slots + 16,
               strerror(-rc));
        want->failed = 1;
        return NULL;
    }
    rc = io_uring_register_file_alloc_range(&ring, 0, want->slots);
    if (rc != 0) {
        printf("ring %d: register_file_alloc_range: %s\n", want->index, strerror(-rc));
        want->failed = 1;
        return NULL;
    }

    void *pool = mmap(NULL, (size_t) want->bufs * 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool == MAP_FAILED) {
        printf("ring %d: mmap pool: %s\n", want->index, strerror(errno));
        want->failed = 1;
        return NULL;
    }
    int bre = 0;
    struct io_uring_buf_ring *br = io_uring_setup_buf_ring(&ring, want->bufs, 1, 0, &bre);
    if (br == NULL) {
        printf("ring %d: setup_buf_ring(%u): %s\n", want->index, want->bufs, strerror(-bre));
        want->failed = 1;
        return NULL;
    }
    printf("ring %d: setup_buf_ring(%u) ok\n", want->index, want->bufs);
    /* The thread stays inside so the ring lives as long as the others,
     * which is what the server does. */
    return NULL;
}

int main(int argc, char **argv)
{
    unsigned entries = argc > 1 ? (unsigned) strtoul(argv[1], NULL, 10) : 32768;
    unsigned slots   = argc > 2 ? (unsigned) strtoul(argv[2], NULL, 10) : 0;
    unsigned bufs    = argc > 3 ? (unsigned) strtoul(argv[3], NULL, 10) : 2048;
    int      rings   = argc > 4 ? atoi(argv[4]) : 1;
    int      threaded = argc > 5 ? atoi(argv[5]) : 0;

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
    printf("asking: entries=%u table_slots=%u bufs=%u rings=%d threaded=%d\n", entries, slots, bufs,
           rings, threaded);

    struct one_ring *want = calloc((size_t) rings, sizeof(*want));
    pthread_t *threads = calloc((size_t) rings, sizeof(*threads));
    if (want == NULL || threads == NULL) {
        printf("out of memory for %d ring(s)\n", rings);
        return 1;
    }
    for (int r = 0; r < rings; r++) {
        want[r].entries = entries;
        want[r].slots = slots;
        want[r].bufs = bufs;
        want[r].index = r;
        if (!threaded) {
            make_ring(&want[r]);
            if (want[r].failed)
                return 1;
            continue;
        }
        if (pthread_create(&threads[r], NULL, make_ring, &want[r]) != 0) {
            printf("ring %d: pthread_create: %s\n", r, strerror(errno));
            return 1;
        }
        /* One at a time, so the output stays in order and a refusal
         * names the ring that met the limit. */
        pthread_join(threads[r], NULL);
        if (want[r].failed)
            return 1;
    }
    printf("all %d ring(s) up\n", rings);
    return 0;
}
