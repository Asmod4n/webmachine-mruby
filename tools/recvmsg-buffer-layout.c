/*
 * Where in a provided buffer does a multishot recvmsg put the payload?
 *
 * The reactor reads an offloaded socket with IORING_OP_RECVMSG so the
 * record type arrives in a control message, and then has to find the
 * plaintext behind a header, a name and that control message. Getting
 * the offset wrong does not fail - it hands the parser bytes that are
 * almost right, which is the hardest kind of wrong to read back.
 *
 * kTLS is not needed to answer it: any cmsg will do, and UDP with
 * IP_PKTINFO produces one on demand. TCP answers the other half, where
 * there is no name and each completion is a read rather than a
 * datagram - which is the shape the reactor actually submits.
 *
 *   cc -O2 -o recvmsg-buffer-layout recvmsg-buffer-layout.c -luring
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <liburing.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFS 8
#define BUFSZ 4096
#define GROUP 1

static int fails;

static void ok(const char *what, int good) {
  printf("  %-56s %s\n", what, good ? "ok" : "FAILED");
  if (!good) fails++;
}

struct rig {
  struct io_uring ring;
  struct io_uring_buf_ring *br;
  char *pool;
};

static int rig_up(struct rig *r) {
  struct io_uring_params p;
  memset(&p, 0, sizeof p);
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
  if (io_uring_queue_init_params(64, &r->ring, &p) != 0) {
    memset(&p, 0, sizeof p);
    if (io_uring_queue_init_params(64, &r->ring, &p) != 0) return -1;
  }
  r->pool = mmap(NULL, (size_t) BUFS * BUFSZ, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (r->pool == MAP_FAILED) return -1;
  int err = 0;
  r->br = io_uring_setup_buf_ring(&r->ring, BUFS, GROUP, 0, &err);
  if (r->br == NULL) return -1;
  const int mask = io_uring_buf_ring_mask(BUFS);
  for (int i = 0; i < BUFS; i++)
    io_uring_buf_ring_add(r->br, r->pool + (size_t) i * BUFSZ, BUFSZ, (unsigned short) i, mask, i);
  io_uring_buf_ring_advance(r->br, BUFS);
  return 0;
}

/* The reactor's own shape: one msghdr that outlives the submit, control
   space reserved, no name asked for on TCP. */
static void arm(struct io_uring *ring, int fd, struct msghdr *msg, size_t namelen,
                size_t controllen) {
  struct io_uring_sqe *s = io_uring_get_sqe(ring);
  memset(msg, 0, sizeof *msg);
  msg->msg_namelen = (socklen_t) namelen;
  msg->msg_controllen = controllen;
  io_uring_prep_recvmsg_multishot(s, fd, msg, 0);
  s->flags |= IOSQE_BUFFER_SELECT;
  s->buf_group = GROUP;
  io_uring_sqe_set_data64(s, 1);
  io_uring_submit(ring);
}

int main(void) {
  struct rig r;
  if (rig_up(&r) != 0) { printf("no ring\n"); return 1; }

  static const char kPayload[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  const size_t plen = sizeof kPayload - 1;

  /* ---- UDP, where a cmsg can be summoned -------------------------- */
  printf("a datagram, with a real control message:\n");
  {
    int rx = socket(AF_INET, SOCK_DGRAM, 0), tx = socket(AF_INET, SOCK_DGRAM, 0);
    const int one = 1;
    setsockopt(rx, IPPROTO_IP, IP_PKTINFO, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(rx, (struct sockaddr *) &a, sizeof a) != 0) { printf("bind\n"); return 1; }
    socklen_t alen = sizeof a;
    getsockname(rx, (struct sockaddr *) &a, &alen);

    struct msghdr msg;
    arm(&r.ring, rx, &msg, sizeof(struct sockaddr_in), CMSG_SPACE(sizeof(struct in_pktinfo)));
    sendto(tx, kPayload, plen, 0, (struct sockaddr *) &a, sizeof a);

    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&r.ring, &cqe);
    ok("a completion arrives with a buffer", (cqe->flags & IORING_CQE_F_BUFFER) != 0);
    const unsigned bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    char *buf = r.pool + (size_t) bid * BUFSZ;

    struct io_uring_recvmsg_out *o = io_uring_recvmsg_validate(buf, cqe->res, &msg);
    ok("the header validates", o != NULL);
    if (o != NULL) {
      int saw_cmsg = 0;
      for (struct cmsghdr *cm = io_uring_recvmsg_cmsg_firsthdr(o, &msg); cm != NULL;
           cm = io_uring_recvmsg_cmsg_nexthdr(o, &msg, cm)) {
        if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) saw_cmsg = 1;
      }
      ok("the control message is where the helpers say", saw_cmsg);
      const void *pay = io_uring_recvmsg_payload(o, &msg);
      const unsigned n = io_uring_recvmsg_payload_length(o, cqe->res, &msg);
      ok("the payload length is the length that was sent", n == plen);
      ok("and the payload is the bytes that were sent",
         n == plen && memcmp(pay, kPayload, plen) == 0);
      ok("which o->payloadlen agrees with", o->payloadlen == plen);
    }
    io_uring_cqe_seen(&r.ring, cqe);
    close(rx);
    close(tx);
  }

  /* ---- TCP, the shape the reactor submits ------------------------- */
  printf("\na stream, no name asked for - what an offloaded socket looks like:\n");
  {
    int ln = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ln, (struct sockaddr *) &a, sizeof a);
    listen(ln, 1);
    socklen_t alen = sizeof a;
    getsockname(ln, (struct sockaddr *) &a, &alen);
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    connect(cl, (struct sockaddr *) &a, sizeof a);
    int sv = accept(ln, NULL, NULL);

    struct msghdr msg;
    arm(&r.ring, sv, &msg, 0, CMSG_SPACE(sizeof(unsigned char)));
    if (write(cl, kPayload, plen) != (ssize_t) plen) { printf("write\n"); return 1; }

    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&r.ring, &cqe);
    const unsigned bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    char *buf = r.pool + (size_t) bid * BUFSZ;
    struct io_uring_recvmsg_out *o = io_uring_recvmsg_validate(buf, cqe->res, &msg);
    ok("the header validates", o != NULL);
    if (o != NULL) {
      printf("    (res %d, namelen %u, controllen %u, payloadlen %u)\n", cqe->res, o->namelen,
             o->controllen, o->payloadlen);
      const void *pay = io_uring_recvmsg_payload(o, &msg);
      const unsigned n = io_uring_recvmsg_payload_length(o, cqe->res, &msg);
      ok("the payload length is what was written", n == plen);
      ok("and the payload starts at the preface, not inside it",
         n >= plen && memcmp(pay, kPayload, plen) == 0);
      if (n != plen || memcmp(pay, kPayload, plen < n ? plen : n) != 0) {
        printf("    got %u bytes: ", n);
        for (unsigned i = 0; i < n && i < 32; i++) {
          const unsigned char c = ((const unsigned char *) pay)[i];
          printf("%c", c >= 32 && c < 127 ? c : '.');
        }
        printf("\n");
      }
      ok("no control message on a socket that is not offloaded",
         io_uring_recvmsg_cmsg_firsthdr(o, &msg) == NULL);
    }
    io_uring_cqe_seen(&r.ring, cqe);
    close(sv);
    close(cl);
    close(ln);
  }

  printf("\n%s\n", fails == 0 ? "all ok - the reactor reads the payload from the right place"
                              : "the buffer layout is not what the reactor assumes");
  io_uring_queue_exit(&r.ring);
  return fails != 0;
}
