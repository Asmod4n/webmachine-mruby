/* Can the children of one supervisor reach each other's rings?
 *
 * The four-process shape needs exactly that: ktls accepts and arms a
 * connection, then pushes the DIRECT descriptor into the webserver's
 * ring with IORING_MSG_SEND_FD, and the webserver pokes back when a
 * record needs the keys turned. One SQE each way, no relay.
 *
 * Two things it may not do. A ring may not be created before fork -
 * that destroys it, the ring belongs to the task that made it. And it
 * may not be driven by two tasks, so SINGLE_ISSUER and DEFER_TASKRUN
 * stay on: without them this reactor loses about 70% of its
 * throughput. MSG_RING does not violate either - the sender submits
 * to its OWN ring and the kernel posts the completion into the
 * target's queue - so the only open question is how the target's ring
 * fd gets to the sender at all.
 *
 * This measures that. Every child builds its own ring after it starts
 * and hands the fd up through a unix socket; the supervisor gives
 * each one the fd of the peer it has to reach.
 *
 *   cc -O2 -o ring-across-processes tools/ring-across-processes.c -luring
 *   ./ring-across-processes
 */
#define _GNU_SOURCE
#include <liburing.h>

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails = 0;

static void ok(int cond, const char *what)
{
  printf("%-58s %s\n", what, cond ? "ok" : "FAIL");
  if (!cond) fails++;
}

/* ---- one descriptor across a unix socket -------------------------- */

static int send_fd(int sock, int fd)
{
  char note = 'x';
  struct iovec io = { .iov_base = &note, .iov_len = 1 };
  union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } u;
  memset(&u, 0, sizeof(u));
  struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1,
                      .msg_control = u.buf, .msg_controllen = CMSG_SPACE(sizeof(int)) };
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(c), &fd, sizeof(int));
  errno = 0;
  return sendmsg(sock, &m, 0) < 0 ? -errno : 0;
}

static int recv_fd(int sock)
{
  char note;
  struct iovec io = { .iov_base = &note, .iov_len = 1 };
  union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } u;
  memset(&u, 0, sizeof(u));
  struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1,
                      .msg_control = u.buf, .msg_controllen = CMSG_SPACE(sizeof(int)) };
  errno = 0;
  if (recvmsg(sock, &m, 0) <= 0) return -errno;
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  if (c == NULL || c->cmsg_type != SCM_RIGHTS) return -ENOMSG;
  int fd = -1;
  memcpy(&fd, CMSG_DATA(c), sizeof(int));
  return fd;
}

static int ring_up(struct io_uring *r, unsigned entries)
{
  struct io_uring_params p;
  memset(&p, 0, sizeof(p));
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
  return io_uring_queue_init_params(entries, r, &p);
}

static int wait_res(struct io_uring *r, unsigned long long *data)
{
  struct io_uring_cqe *c;
  if (io_uring_wait_cqe(r, &c) < 0) return -1;
  const int res = c->res;
  if (data != NULL) *data = c->user_data;
  io_uring_cqe_seen(r, c);
  return res;
}

/* ---- the ktls child ----------------------------------------------- */

static int child_ktls(int up, int conn)
{
  struct io_uring ring;
  const int rc = ring_up(&ring, 32);
  if (rc != 0) { fprintf(stderr, "ktls : ring: %s\n", strerror(-rc)); return 1; }

  int files[1] = { conn };
  io_uring_register_files(&ring, files, 1);
  close(conn);                      /* slot 0 is the only reference now */

  const int sent = send_fd(up, ring.ring_fd);
  if (sent != 0) {
    fprintf(stderr, "ktls : could not hand its ring fd up: %s\n", strerror(-sent));
    return 2;
  }
  const int web_ring = recv_fd(up);
  if (web_ring < 0) { fprintf(stderr, "ktls : no peer ring: %s\n", strerror(-web_ring)); return 2; }

  /* stands in for setsockopt(TCP_ULP) and the two crypto_info blobs */
  int one = 1;
  struct io_uring_sqe *s = io_uring_get_sqe(&ring);
  io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, 0, IPPROTO_TCP, TCP_NODELAY,
                         &one, sizeof(one));
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_submit(&ring);
  if (wait_res(&ring, NULL) != 0) { fprintf(stderr, "ktls : arming failed\n"); return 1; }

  /* the descriptor into the other process's ring, ALPN beside it */
  s = io_uring_get_sqe(&ring);
  io_uring_prep_msg_ring_fd(s, web_ring, 0, IORING_FILE_INDEX_ALLOC, 0x6832 /* "h2" */, 0);
  io_uring_submit(&ring);
  const int pushed = wait_res(&ring, NULL);
  fprintf(stderr, "ktls : MSG_SEND_FD into the webserver's ring -> %d\n", pushed);
  if (pushed != 0) return 1;

  /* it must still own the connection, or a rekey later is impossible */
  s = io_uring_get_sqe(&ring);
  io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, 0, IPPROTO_TCP, TCP_NODELAY,
                         &one, sizeof(one));
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_submit(&ring);
  const int still = wait_res(&ring, NULL);
  fprintf(stderr, "ktls : still owns its slot afterwards -> %d\n", still);

  unsigned long long why = 0;
  const int slot = wait_res(&ring, &why);
  fprintf(stderr, "ktls : the webserver says slot %d wants work (0x%llx)\n", slot, why);
  return (still == 0 && why == 0x2216) ? 0 : 1;
}

/* ---- the webserver child ------------------------------------------ */

static int child_web(int up, int ktls_pid_unused)
{
  (void) ktls_pid_unused;
  struct io_uring ring;
  const int rc = ring_up(&ring, 32);
  if (rc != 0) { fprintf(stderr, "web  : ring: %s\n", strerror(-rc)); return 1; }
  int none[8];
  for (int i = 0; i < 8; i++) none[i] = -1;
  io_uring_register_files(&ring, none, 8);

  const int sent = send_fd(up, ring.ring_fd);
  if (sent != 0) {
    fprintf(stderr, "web  : could not hand its ring fd up: %s\n", strerror(-sent));
    return 2;
  }
  const int ktls_ring = recv_fd(up);
  if (ktls_ring < 0) { fprintf(stderr, "web  : no peer ring: %s\n", strerror(-ktls_ring)); return 2; }

  unsigned long long alpn = 0;
  const int slot = wait_res(&ring, &alpn);
  fprintf(stderr, "web  : got slot %d, alpn 0x%llx\n", slot, alpn);
  if (slot < 0) return 1;

  struct io_uring_sqe *s = io_uring_get_sqe(&ring);
  io_uring_prep_send(s, slot, "served-by-web", 13, 0);
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_submit(&ring);
  const int wrote = wait_res(&ring, NULL);
  fprintf(stderr, "web  : sent on a socket it never opened -> %d\n", wrote);

  /* "slot N carries a record type 22" - the rekey poke */
  s = io_uring_get_sqe(&ring);
  io_uring_prep_msg_ring(s, ktls_ring, slot, 0x2216, 0);
  io_uring_submit(&ring);
  (void) wait_res(&ring, NULL);
  return wrote == 13 ? 0 : 1;
}

int main(void)
{
  struct utsname u;
  uname(&u);
  printf("kernel %s\n\n", u.release);

  /* Does a ring fd cross a unix socket at all? A plain socket is the
   * control: if that passes and the ring does not, the refusal is
   * about io_uring and not about this code. */
  {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct io_uring r;
    const int rc = ring_up(&r, 8);
    ok(rc == 0, "a ring with SINGLE_ISSUER | DEFER_TASKRUN comes up");
    if (rc != 0) { printf("  %s\n", strerror(-rc)); return 1; }
    int plain = socket(AF_INET, SOCK_STREAM, 0);
    const int a = send_fd(sv[0], plain);
    const int b = send_fd(sv[0], r.ring_fd);
    ok(a == 0, "SCM_RIGHTS carries a plain socket fd");
    printf("  (ring fd over SCM_RIGHTS -> %d%s%s)\n", b, b < 0 ? ", " : "",
           b < 0 ? strerror(-b) : "");
    ok(b == 0, "SCM_RIGHTS carries an io_uring fd");
    close(plain);
    close(sv[0]);
    close(sv[1]);
    io_uring_queue_exit(&r);
    if (b != 0) {
      printf("\nThe ring fd cannot leave this process. Everything below needs it,\n"
             "so nothing further is measured here.\n");
      return 1;
    }
  }

  /* a connected pair, standing in for an accepted connection */
  int lst = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(lst, (struct sockaddr *) &a, sizeof(a));
  listen(lst, 1);
  socklen_t al = sizeof(a);
  getsockname(lst, (struct sockaddr *) &a, &al);
  int peer = socket(AF_INET, SOCK_STREAM, 0);
  connect(peer, (struct sockaddr *) &a, sizeof(a));
  int conn = accept(lst, NULL, NULL);
  close(lst);

  int k[2], w[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, k);
  socketpair(AF_UNIX, SOCK_STREAM, 0, w);

  /* The supervisor forks FIRST and touches no ring: one created before
   * the fork would not survive it. */
  const pid_t kp = fork();
  if (kp == 0) { close(k[0]); close(w[0]); close(w[1]); close(peer); close(lst);
                 _exit(child_ktls(k[1], conn)); }
  const pid_t wp = fork();
  if (wp == 0) { close(w[0]); close(k[0]); close(k[1]); close(peer); close(conn);
                 _exit(child_web(w[1], (int) kp)); }
  close(k[1]);
  close(w[1]);
  close(conn);

  const int ktls_ring = recv_fd(k[0]);
  const int web_ring = recv_fd(w[0]);
  ok(ktls_ring >= 0 && web_ring >= 0, "the supervisor collects both children's ring fds");
  if (ktls_ring >= 0 && web_ring >= 0) {
    ok(send_fd(k[0], web_ring) == 0 && send_fd(w[0], ktls_ring) == 0,
       "and hands each the one it has to reach");
  }

  char buf[64];
  memset(buf, 0, sizeof(buf));
  const ssize_t n = read(peer, buf, sizeof(buf));
  ok(n == 13 && memcmp(buf, "served-by-web", 13) == 0,
     "the peer is served by the process that never opened its socket");

  int ks = 1, ws = 1;
  waitpid(kp, &ks, 0);
  waitpid(wp, &ws, 0);
  ok(WIFEXITED(ks) && WEXITSTATUS(ks) == 0, "ktls: pushed the descriptor and kept its slot");
  ok(WIFEXITED(ws) && WEXITSTATUS(ws) == 0, "web: served on it and poked back");

  printf("\n%s\n", fails == 0 ? "all ok - the children reach each other's rings"
                              : "FAILURES");
  return fails != 0;
}
