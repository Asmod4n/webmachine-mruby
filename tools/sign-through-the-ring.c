/*
 * What does it cost to let another process hold the private key?
 *
 * The handshake needs ONE signature per new connection, and the only
 * bytes that cross are the hash going out and the signature coming
 * back. No descriptor moves - the socketpair to the key process is
 * registered in this ring once, at boot, and every request after that
 * is a send and a recv on a fixed file, riding the submit that was
 * happening anyway.
 *
 * Three numbers, so the question is answerable rather than arguable:
 * the signature alone, the signature through the ring to another
 * process, and the same with both pinned to one core.
 *
 *   cc -O2 -o sign-through-the-ring sign-through-the-ring.c -luring -lcrypto
 */
#define _GNU_SOURCE
#include <liburing.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 5000
#define HASHLEN 32
#define SIGMAX 128

static double now_us(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1e6 + (double) t.tv_nsec / 1e3;
}

static EVP_PKEY *keygen_p256(void) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

/* RFC 8446 4.4.3's signature, over a hash somebody else computed. */
static size_t sign_digest(EVP_PKEY *pkey, const unsigned char *hash, unsigned char *out) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  size_t len = SIGMAX;
  EVP_PKEY_sign_init(ctx);
  EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
  EVP_PKEY_sign(ctx, out, &len, hash, HASHLEN);
  EVP_PKEY_CTX_free(ctx);
  return len;
}

/* The key process: it has the key, it never sees a socket. */
static void key_daemon(int fd, int pin) {
  if (pin >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(pin, &set);
    sched_setaffinity(0, sizeof set, &set);
  }
  EVP_PKEY *pkey = keygen_p256();
  unsigned char hash[HASHLEN], sig[SIGMAX];
  for (;;) {
    ssize_t n = read(fd, hash, sizeof hash);
    if (n != (ssize_t) sizeof hash) break;
    const size_t siglen = sign_digest(pkey, hash, sig);
    if (write(fd, sig, siglen) != (ssize_t) siglen) break;
  }
  EVP_PKEY_free(pkey);
  _exit(0);
}

/* One request through the ring: send the hash, recv the signature.
   Linked, so both go in on one submit and the reactor waits once. */
static int ask_for_a_signature(struct io_uring *ring, unsigned char *hash, unsigned char *sig) {
  struct io_uring_sqe *s = io_uring_get_sqe(ring);
  io_uring_prep_send(s, 0, hash, HASHLEN, 0);
  s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
  s = io_uring_get_sqe(ring);
  io_uring_prep_recv(s, 0, sig, SIGMAX, 0);
  s->flags |= IOSQE_FIXED_FILE;

  io_uring_submit_and_wait(ring, 2);
  int got = 0;
  for (int i = 0; i < 2; i++) {
    struct io_uring_cqe *cqe;
    if (io_uring_wait_cqe(ring, &cqe) != 0) return -1;
    if (cqe->res < 0) return -1;
    got = cqe->res;
    io_uring_cqe_seen(ring, cqe);
  }
  return got;
}

static double measure(int pin_daemon_to, const char *label) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;

  const pid_t child = fork();
  if (child == 0) {
    close(sv[0]);
    key_daemon(sv[1], pin_daemon_to);
  }
  close(sv[1]);

  if (pin_daemon_to >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(pin_daemon_to, &set);
    sched_setaffinity(0, sizeof set, &set);
  }

  /* The reactor's own ring flags - the ones a 70% throughput difference
     rests on, so the number is measured under them and not beside them. */
  struct io_uring ring;
  struct io_uring_params p;
  memset(&p, 0, sizeof p);
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
  if (io_uring_queue_init_params(64, &ring, &p) != 0) {
    memset(&p, 0, sizeof p);
    if (io_uring_queue_init_params(64, &ring, &p) != 0) return -1;
    fprintf(stderr, "  (no SINGLE_ISSUER/DEFER_TASKRUN on this kernel)\n");
  }
  io_uring_register_files(&ring, &sv[0], 1);

  unsigned char hash[HASHLEN], sig[SIGMAX];
  memset(hash, 0xa5, sizeof hash);
  for (int i = 0; i < 200; i++) ask_for_a_signature(&ring, hash, sig);  /* warm */

  const double t0 = now_us();
  for (int i = 0; i < ROUNDS; i++) {
    if (ask_for_a_signature(&ring, hash, sig) <= 0) {
      fprintf(stderr, "round %d failed\n", i);
      break;
    }
  }
  const double per = (now_us() - t0) / ROUNDS;
  printf("  %-46s %7.2f us\n", label, per);

  io_uring_queue_exit(&ring);
  close(sv[0]);
  kill(child, 9);
  waitpid(child, NULL, 0);
  return per;
}

int main(void) {
  printf("one ECDSA P-256 signature, %d rounds each\n\n", ROUNDS);

  EVP_PKEY *pkey = keygen_p256();
  unsigned char hash[HASHLEN], sig[SIGMAX];
  memset(hash, 0xa5, sizeof hash);
  for (int i = 0; i < 200; i++) sign_digest(pkey, hash, sig);
  const double t0 = now_us();
  for (int i = 0; i < ROUNDS; i++) sign_digest(pkey, hash, sig);
  const double own = (now_us() - t0) / ROUNDS;
  EVP_PKEY_free(pkey);
  printf("  %-46s %7.2f us\n", "in this process, holding the key", own);

  const double free_placement = measure(-1, "through the ring, key in another process");
  const double pinned = measure(0, "the same, both pinned to one core");

  printf("\nwhat privilege separation costs per new connection:\n");
  printf("  %-46s %+7.2f us\n", "wherever the scheduler puts them", free_placement - own);
  printf("  %-46s %+7.2f us\n", "pinned together", pinned - own);
  return 0;
}
