// The server binary. Today it is the floor: accept, read, answer a
// fixed 200 (or echo, for the byte-proof bintest). Every later layer
// grows inside Ring; this file stays the CLI.
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../../src/ring.hpp"

int main(int argc, char** argv) {
  webmachine::RingConfig cfg;
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--unix") == 0 && i + 1 < argc) {
      cfg.unix_path = argv[++i];
    } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      cfg.port = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--echo") == 0) {
      cfg.echo = true;
    } else {
      std::fprintf(stderr, "usage: %s (--unix PATH | --port N) [--echo]\n", argv[0]);
      return 2;
    }
  }
  if ((cfg.unix_path == nullptr) == (cfg.port == 0)) {
    std::fprintf(stderr, "exactly one of --unix or --port\n");
    return 2;
  }

  webmachine::Ring ring;
  char err[256];
  if (!ring.init(cfg, err, sizeof(err))) {
    std::fprintf(stderr, "webmachine: %s\n", err);
    return 1;
  }
  std::fprintf(stderr, "webmachine: floor up, pid %d, %s%s\n", getpid(),
               cfg.unix_path ? cfg.unix_path : "tcp", cfg.echo ? ", echo" : "");
  ring.run();
}
