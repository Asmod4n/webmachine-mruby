/*
 * Do the ring's blocking-io workers inherit the reactor's affinity, and
 * can they be given their own?
 *
 * The question decides whether a reactor may be pinned at all. io-wq
 * threads are created by the task that owns the ring, so pinning the
 * reactor to one core would put every operation the kernel cannot do
 * inline - an openat, a read that would block - on that same core,
 * queued behind the reactor itself.
 *
 * IORING_REGISTER_IOWQ_AFF exists for exactly this. Whether it does
 * what its name says is what this measures, by reading the workers'
 * own Cpus_allowed_list out of /proc rather than trusting that the
 * register call returned 0. Each case runs in its own process, because
 * a worker already spawned is the thing most likely to confuse the
 * answer.
 *
 *   cc -O2 -o iowq-affinity iowq-affinity.c -luring
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <liburing.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* One line of /proc/self/task/<tid>/<file>, by prefix. */
static void proc_field(const char *tid, const char *file, const char *key, char *out, size_t cap) {
  char path[512];
  out[0] = '\0';
  snprintf(path, sizeof path, "/proc/self/task/%s/%s", tid, file);
  FILE *f = fopen(path, "r");
  if (f == NULL) return;
  char line[512];
  const size_t keylen = strlen(key);
  while (fgets(line, sizeof line, f) != NULL) {
    if (keylen != 0 && strncmp(line, key, keylen) != 0) continue;
    char *v = line + keylen;
    while (*v == '\t' || *v == ' ') v++;
    v[strcspn(v, "\n")] = '\0';
    snprintf(out, cap, "%s", v);
    break;
  }
  fclose(f);
}

/* The workers are threads of this process, named iou-wrk-<pid>. */
static int report_workers(void) {
  DIR *d = opendir("/proc/self/task");
  struct dirent *e;
  int found = 0;
  if (d == NULL) return 0;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') continue;
    char comm[64], cpus[256];
    proc_field(e->d_name, "comm", "", comm, sizeof comm);
    if (strncmp(comm, "iou-wrk", 7) != 0) continue;
    proc_field(e->d_name, "status", "Cpus_allowed_list:", cpus, sizeof cpus);
    printf("      %s (tid %s) runs on cpu %s\n", comm, e->d_name, cpus);
    found++;
  }
  closedir(d);
  if (found == 0) printf("      (no workers alive)\n");
  return found;
}

/* IOSQE_ASYNC is the shortest way to make the kernel hand an operation
   to io-wq instead of trying it inline. */
static void park_a_read_on_iowq(struct io_uring *ring) {
  int fds[2];
  if (pipe(fds) != 0) return;
  struct io_uring_sqe *s = io_uring_get_sqe(ring);
  char buf[8];
  io_uring_prep_read(s, fds[0], buf, sizeof buf, 0);
  s->flags |= IOSQE_ASYNC;
  io_uring_submit(ring);
  usleep(80 * 1000);  /* the kernel spawns the worker, not us */
  report_workers();
  if (write(fds[1], "x", 1) != 1) { /* let the read complete */
  }
  struct io_uring_cqe *cqe;
  io_uring_wait_cqe(ring, &cqe);
  io_uring_cqe_seen(ring, cqe);
  close(fds[0]);
  close(fds[1]);
}

static void own_affinity(char *out, size_t cap) {
  char tid[32];
  snprintf(tid, sizeof tid, "%d", (int) getpid());
  proc_field(tid, "status", "Cpus_allowed_list:", out, cap);
}

/* pin_to < 0 leaves the reactor where it is. register_before decides
   whether IOWQ_AFF is set before the first worker ever exists. */
static void one_case(const char *title, int pin_to, int register_before, long ncpu) {
  fflush(stdout);
  const pid_t kid = fork();
  if (kid != 0) {
    waitpid(kid, NULL, 0);
    return;
  }
  printf("  %s\n", title);
  if (pin_to >= 0) {
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(pin_to, &one);
    if (sched_setaffinity(0, sizeof one, &one) != 0) perror("sched_setaffinity");
  }
  struct io_uring ring;
  struct io_uring_params p;
  memset(&p, 0, sizeof p);
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
  if (io_uring_queue_init_params(64, &ring, &p) != 0) {
    fflush(stdout);
    _exit(1);
  }

  char mine[256];
  own_affinity(mine, sizeof mine);
  printf("      the reactor thread runs on cpu %s\n", mine);

  if (register_before) {
    cpu_set_t rest;
    CPU_ZERO(&rest);
    for (long i = 1; i < ncpu; i++) CPU_SET(i, &rest);
    const int rc = io_uring_register_iowq_aff(&ring, sizeof rest, &rest);
    printf("      IOWQ_AFF asked for cpu 1-%ld: %s\n", ncpu - 1,
           rc == 0 ? "returned 0" : strerror(-rc));
  }
  park_a_read_on_iowq(&ring);
  io_uring_queue_exit(&ring);
  fflush(stdout);
  _exit(0);
}

int main(void) {
  const long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
  printf("%ld cpus online\n\n", ncpu);

  one_case("1. reactor pinned to cpu 0, io-wq never told anything:", 0, 0, ncpu);
  printf("\n");
  one_case("2. reactor pinned to cpu 0, IOWQ_AFF set before any worker exists:", 0, 1, ncpu);
  printf("\n");
  one_case("3. reactor not pinned at all, IOWQ_AFF set anyway:", -1, 1, ncpu);
  return 0;
}
