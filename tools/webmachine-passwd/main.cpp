// Design decisions live in .DESIGN.md, filed under what each comment names.
//
// webmachine-passwd - the password database the server verifies against.
// htpasswd's job, with LMDB where htpasswd has a text file, and argon2id
// where it has crypt().
//
// What a record IS: the key is the user name, the value is a PasswdRec
// (src/webmachine.hpp) followed by its salt and its hash. The cost is a
// property of the RECORD, so raising it later re-hashes a user at their
// next password change and leaves everyone else verifiable meanwhile.
//
// Not argon2's encoded string, though it would have been the smaller
// thing to keep in step: that form cannot carry ad, and ad is what binds
// a record to the sub-database it lives in.
//
// What separates one set of users from another is a NAMED sub-database,
// not a prefix inside the key. LMDB gives each name its own B-tree, so
// two sets cannot collide and neither is scanned to reach the other.
#include <lmdb.h>
#include <sys/random.h>
#include <termios.h>
#include <unistd.h>

#include <argon2.h>

#include "../../src/webmachine.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace {

// OWASP's Password Storage Cheat Sheet, the Argon2id section: five
// settings it calls an EQUAL level of defence, differing only in the
// trade between memory and time. They are listed rather than computed
// because the equal-defence claim is theirs, and a pair between two rows
// would be this tool's own assertion with nobody behind it.
struct Cost {
  uint32_t m_kib;
  uint32_t t;
  uint32_t p;
};
constexpr Cost kCosts[] = {
    {47104, 1, 1},  // 46 MiB
    {19456, 2, 1},  // 19 MiB - the default, and OWASP's stated minimum
    {12288, 3, 1},  // 12 MiB
    {9216, 4, 1},   // 9 MiB
    {7168, 5, 1},   // 7 MiB
};
constexpr size_t kCostCount = sizeof kCosts / sizeof kCosts[0];
constexpr size_t kDefaultCost = 1;

constexpr size_t kSaltLen = 16;
constexpr size_t kHashLen = 32;
// A password longer than this is not a password. The server's own head
// ceiling is 8 KiB for EVERY field together, so anything near it would
// be an attack on the worker pool rather than a login.
constexpr size_t kMaxPassword = 512;

[[noreturn]] void die(const char* what, const char* why) {
  std::fprintf(stderr, "webmachine-passwd: %s: %s\n", what, why);
  std::exit(1);
}

void die_mdb(const char* what, int rc) { die(what, mdb_strerror(rc)); }

// Overwrite through a volatile pointer: a plain memset on a buffer that
// is never read again is dead-store-eliminated by any optimiser, and the
// password stays in the frame.
void wipe(char* p, size_t n) {
  volatile char* v = p;
  while (n-- > 0) *v++ = 0;
}

// RFC-nothing: the password comes from the terminal with echo off, never
// from argv. /proc/<pid>/cmdline is readable by others and the shell
// keeps a history; a password given as an argument is a password given
// away. /dev/tty and not stdin, so a piped stdin cannot silently turn
// this into an unprompted read.
std::string ask(const char* prompt) {
  FILE* tty = std::fopen("/dev/tty", "r+");
  if (tty == nullptr) die("/dev/tty", std::strerror(errno));
  const int fd = fileno(tty);

  struct termios was {};
  if (tcgetattr(fd, &was) != 0) die("tcgetattr", std::strerror(errno));
  struct termios now = was;
  now.c_lflag = static_cast<tcflag_t>(now.c_lflag & ~ECHO);
  if (tcsetattr(fd, TCSAFLUSH, &now) != 0) die("tcsetattr", std::strerror(errno));

  std::fputs(prompt, tty);
  std::fflush(tty);
  char buf[kMaxPassword + 2];
  char* got = std::fgets(buf, sizeof buf, tty);

  tcsetattr(fd, TCSAFLUSH, &was);
  std::fputc('\n', tty);
  std::fclose(tty);

  if (got == nullptr) die("read password", "no input");
  size_t n = std::strlen(buf);
  if (n > 0 && buf[n - 1] == '\n') buf[--n] = '\0';
  if (n == 0) die("read password", "empty");
  if (n > kMaxPassword) die("read password", "longer than 512 bytes");
  std::string out(buf, n);
  wipe(buf, sizeof buf);
  return out;
}

// The environment, opened for what this invocation does. MDB_NOSUBDIR so
// the database is the FILE the operator named - conf.auth.db points at a
// file, not at a directory with a data and a lock file in it.
MDB_env* open_env(const char* path, unsigned flags, unsigned maxdbs, size_t mapsize) {
  MDB_env* env = nullptr;
  int rc = mdb_env_create(&env);
  if (rc != 0) die_mdb("mdb_env_create", rc);
  // Both are decided when the file is made and cannot be raised by a
  // reader afterwards, which is why create takes them as options.
  rc = mdb_env_set_maxdbs(env, maxdbs);
  if (rc != 0) die_mdb("mdb_env_set_maxdbs", rc);
  rc = mdb_env_set_mapsize(env, mapsize);
  if (rc != 0) die_mdb("mdb_env_set_mapsize", rc);
  rc = mdb_env_open(env, path, flags | MDB_NOSUBDIR, 0600);
  if (rc != 0) die_mdb(path, rc);
  return env;
}

// One hash, as the record the server will verify against.
//
// The context API and not argon2id_hash_encoded, because ad only exists
// here. ad is the sub-database's name: the same password in two sets
// hashes to two different values, and a row moved between them stops
// verifying.
std::string hash_password(const std::string& password, Cost c, const char* ad, int64_t ctime,
                          int64_t mtime) {
  unsigned char salt[kSaltLen];
  if (getrandom(salt, sizeof salt, 0) != static_cast<ssize_t>(sizeof salt)) {
    die("getrandom", std::strerror(errno));
  }
  unsigned char raw[kHashLen];

  argon2_context ctx {};
  ctx.out = raw;
  ctx.outlen = kHashLen;
  ctx.pwd = reinterpret_cast<uint8_t*>(const_cast<char*>(password.data()));
  ctx.pwdlen = static_cast<uint32_t>(password.size());
  ctx.salt = salt;
  ctx.saltlen = kSaltLen;
  ctx.ad = reinterpret_cast<uint8_t*>(const_cast<char*>(ad));
  ctx.adlen = static_cast<uint32_t>(std::strlen(ad));
  ctx.t_cost = c.t;
  ctx.m_cost = c.m_kib;
  ctx.lanes = c.p;
  ctx.threads = c.p;
  ctx.version = ARGON2_VERSION_NUMBER;
  ctx.flags = ARGON2_DEFAULT_FLAGS;

  // argon2_ctx and not argon2id_ctx: the same call with the type named
  // rather than baked into the function's name, so the record and the
  // call say Argon2_id in the same place.
  const int rc = argon2_ctx(&ctx, Argon2_id);
  if (rc != ARGON2_OK) die("argon2_ctx", argon2_error_message(rc));

  webmachine::PasswdRec rec {};
  rec.version = webmachine::kPasswdRecVersion;
  rec.salt_len = kSaltLen;
  rec.hash_len = kHashLen;
  rec.lanes = static_cast<uint8_t>(c.p);
  rec.m_kib = c.m_kib;
  rec.t = c.t;
  rec.ctime = ctime;
  rec.mtime = mtime;

  std::string out;
  out.append(reinterpret_cast<const char*>(&rec), sizeof rec);
  out.append(reinterpret_cast<const char*>(salt), kSaltLen);
  out.append(reinterpret_cast<const char*>(raw), kHashLen);
  wipe(reinterpret_cast<char*>(raw), sizeof raw);
  return out;
}

double seconds_for(Cost c) {
  const std::string pw = "measurement, not a password";
  const char* const ad = "calibration";
  struct timespec a {};
  clock_gettime(CLOCK_MONOTONIC, &a);
  const std::string out = hash_password(pw, c, ad, 0, 0);
  struct timespec b {};
  clock_gettime(CLOCK_MONOTONIC, &b);
  (void)out.size();
  return static_cast<double>(b.tv_sec - a.tv_sec) +
         static_cast<double>(b.tv_nsec - a.tv_nsec) / 1e9;
}

// What a row costs HERE. The operator names a time budget; the row with
// the most memory that fits it wins, because memory is what argon2
// spends against an attacker's hardware and iterations are the cheaper
// half of the same defence.
size_t calibrate(double budget_s, unsigned workers, bool say) {
  size_t best = kCostCount - 1;
  for (size_t i = 0; i < kCostCount; i++) {
    const double took = seconds_for(kCosts[i]);
    if (say) {
      std::fprintf(stderr, "  m=%u (%u MiB) t=%u p=%u  %6.1f ms  %6.1f logins/s with %u workers\n",
                   kCosts[i].m_kib, kCosts[i].m_kib / 1024, kCosts[i].t, kCosts[i].p,
                   took * 1000.0, static_cast<double>(workers) / took, workers);
    }
    if (took <= budget_s) {
      best = i;
      break;
    }
  }
  return best;
}

void usage() {
  std::fprintf(stderr,
               "usage: webmachine-passwd COMMAND [OPTIONS]\n"
               "\n"
               "  create FILE            make the database\n"
               "  add    FILE DB USER    add a user, refusing one that exists\n"
               "  set    FILE DB USER    add or replace a user\n"
               "  del    FILE DB USER    remove a user\n"
               "  list   FILE DB         the users, when they were made and last changed\n"
               "  calibrate              what each cost setting takes here\n"
               "\n"
               "DB names a sub-database inside FILE - one set of users. The\n"
               "server is pointed at the same pair.\n"
               "\n"
               "OPTIONS\n"
               "  --maxdbs N       how many sub-databases FILE may ever hold (16)\n"
               "  --mapsize MiB    the ceiling FILE may grow to (64)\n"
               "  --time MS        the time one login may cost; picks the cost (0 = default)\n"
               "  --workers N      how many hashes run at once, for the rate this prints (8)\n"
               "  --sort HOW       list order: user, created or changed (user)\n"
               "  --names          list bare names, for a script to read\n");
  std::exit(2);
}

// What list is ordered by. Key order is LMDB's own and costs nothing;
// the two times are read out of the records and sorted here.
enum class Sort : uint8_t { kUser, kCtime, kMtime };

struct Row {
  std::string user;
  webmachine::PasswdRec rec {};
};

// ISO 8601, UTC, seconds. A user list is read by a person and compared
// across machines; a local time would be neither.
void spell_time(int64_t t, char* out, size_t n) {
  const std::time_t tt = static_cast<std::time_t>(t);
  struct tm tm {};
  gmtime_r(&tt, &tm);
  std::strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

struct Options {
  Sort sort = Sort::kUser;
  bool plain = false;
  unsigned maxdbs = 16;
  size_t mapsize_mib = 64;
  double time_ms = 0;
  unsigned workers = 8;
};

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) usage();
  const char* cmd = argv[1];

  Options o;
  const char* positional[3] = {nullptr, nullptr, nullptr};
  size_t npos = 0;
  for (int i = 2; i < argc; i++) {
    if (std::strcmp(argv[i], "--maxdbs") == 0 && i + 1 < argc) {
      o.maxdbs = static_cast<unsigned>(std::atoi(argv[++i]));
    } else if (std::strcmp(argv[i], "--mapsize") == 0 && i + 1 < argc) {
      o.mapsize_mib = static_cast<size_t>(std::atoll(argv[++i]));
    } else if (std::strcmp(argv[i], "--time") == 0 && i + 1 < argc) {
      o.time_ms = std::atof(argv[++i]);
    } else if (std::strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
      o.workers = static_cast<unsigned>(std::atoi(argv[++i]));
    } else if (std::strcmp(argv[i], "--sort") == 0 && i + 1 < argc) {
      const char* how = argv[++i];
      if (std::strcmp(how, "user") == 0) {
        o.sort = Sort::kUser;
      } else if (std::strcmp(how, "created") == 0) {
        o.sort = Sort::kCtime;
      } else if (std::strcmp(how, "changed") == 0) {
        o.sort = Sort::kMtime;
      } else {
        die("--sort", "user, created or changed");
      }
    } else if (std::strcmp(argv[i], "--names") == 0) {
      o.plain = true;
    } else if (argv[i][0] == '-') {
      usage();
    } else if (npos < 3) {
      positional[npos++] = argv[i];
    } else {
      usage();
    }
  }
  if (o.workers == 0) o.workers = 1;
  const size_t mapsize = o.mapsize_mib * 1024 * 1024;

  if (std::strcmp(cmd, "calibrate") == 0) {
    std::fprintf(stderr, "argon2id on this machine:\n");
    const size_t pick = calibrate(o.time_ms > 0 ? o.time_ms / 1000.0 : 1e9, o.workers, true);
    if (o.time_ms > 0) {
      std::fprintf(stderr, "\nwithin %.0f ms: m=%u t=%u p=%u\n", o.time_ms, kCosts[pick].m_kib,
                   kCosts[pick].t, kCosts[pick].p);
    }
    return 0;
  }

  if (std::strcmp(cmd, "create") == 0) {
    if (positional[0] == nullptr) usage();
    MDB_env* env = open_env(positional[0], 0, o.maxdbs, mapsize);
    mdb_env_close(env);
    std::fprintf(stderr, "webmachine-passwd: %s, up to %u sub-databases, up to %zu MiB\n",
                 positional[0], o.maxdbs, o.mapsize_mib);
    return 0;
  }

  const bool adding = std::strcmp(cmd, "add") == 0;
  const bool setting = std::strcmp(cmd, "set") == 0;
  const bool deleting = std::strcmp(cmd, "del") == 0;
  const bool listing = std::strcmp(cmd, "list") == 0;
  if (!adding && !setting && !deleting && !listing) usage();
  if (positional[0] == nullptr || positional[1] == nullptr) usage();
  if (!listing && positional[2] == nullptr) usage();

  const char* file = positional[0];
  const char* dbname = positional[1];
  const char* user = positional[2];

  MDB_env* env = open_env(file, listing ? MDB_RDONLY : 0, o.maxdbs, mapsize);
  MDB_txn* txn = nullptr;
  int rc = mdb_txn_begin(env, nullptr, listing ? MDB_RDONLY : 0, &txn);
  if (rc != 0) die_mdb("mdb_txn_begin", rc);
  MDB_dbi dbi = 0;
  rc = mdb_dbi_open(txn, dbname, listing ? 0 : MDB_CREATE, &dbi);
  if (rc != 0) die_mdb(dbname, rc);

  if (listing) {
    MDB_cursor* cur = nullptr;
    rc = mdb_cursor_open(txn, dbi, &cur);
    if (rc != 0) die_mdb("mdb_cursor_open", rc);
    // Read the whole set, then order it. A cursor walks LMDB's own
    // ordering, which is the key's, and any other order has to be made
    // here - so it is made once, in memory, over a set an operator can
    // read. An index sub-database keyed by time would keep a second
    // structure true for a list nobody pages through.
    std::vector<Row> rows;
    MDB_val k {}, v {};
    while ((rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT)) == 0) {
      Row row;
      row.user.assign(static_cast<const char*>(k.mv_data), k.mv_size);
      if (v.mv_size >= sizeof(webmachine::PasswdRec)) {
        std::memcpy(&row.rec, v.mv_data, sizeof row.rec);
      }
      rows.push_back(row);
    }
    mdb_cursor_close(cur);

    if (o.sort == Sort::kCtime) {
      std::stable_sort(rows.begin(), rows.end(),
                       [](const Row& a, const Row& b) { return a.rec.ctime < b.rec.ctime; });
    } else if (o.sort == Sort::kMtime) {
      std::stable_sort(rows.begin(), rows.end(),
                       [](const Row& a, const Row& b) { return a.rec.mtime < b.rec.mtime; });
    }

    for (const Row& row : rows) {
      if (o.plain) {
        std::fwrite(row.user.data(), 1, row.user.size(), stdout);
        std::fputc('\n', stdout);
        continue;
      }
      char c[32] = "-";
      char m[32] = "-";
      if (row.rec.ctime != 0) spell_time(row.rec.ctime, c, sizeof c);
      if (row.rec.mtime != 0) spell_time(row.rec.mtime, m, sizeof m);
      std::printf("%-24s  created %s  changed %s  m=%u t=%u\n", row.user.c_str(), c, m,
                  row.rec.m_kib, row.rec.t);
    }
    mdb_txn_abort(txn);
    mdb_env_close(env);
    return 0;
  }

  MDB_val key {};
  key.mv_size = std::strlen(user);
  key.mv_data = const_cast<char*>(user);

  if (deleting) {
    rc = mdb_del(txn, dbi, &key, nullptr);
    if (rc == MDB_NOTFOUND) die(user, "no such user");
    if (rc != 0) die_mdb("mdb_del", rc);
  } else {
    const size_t pick =
        o.time_ms > 0 ? calibrate(o.time_ms / 1000.0, o.workers, false) : kDefaultCost;
    std::string pw = ask("Password: ");
    std::string again = ask("Again: ");
    if (pw != again) {
      wipe(pw.data(), pw.size());
      wipe(again.data(), again.size());
      die("password", "the two did not match");
    }
    wipe(again.data(), again.size());
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    // set REPLACES a password and keeps the day the user was created;
    // only add starts one. An operator asking "who is new here" wants
    // the answer not to move every time somebody changes a password.
    int64_t created = now;
    if (setting) {
      MDB_val had {};
      if (mdb_get(txn, dbi, &key, &had) == 0 && had.mv_size >= sizeof(webmachine::PasswdRec)) {
        webmachine::PasswdRec old {};
        std::memcpy(&old, had.mv_data, sizeof old);
        if (old.ctime != 0) created = old.ctime;
      }
    }
    std::string encoded = hash_password(pw, kCosts[pick], dbname, created, now);
    wipe(pw.data(), pw.size());

    MDB_val val {};
    val.mv_size = encoded.size();
    val.mv_data = encoded.data();
    rc = mdb_put(txn, dbi, &key, &val, adding ? MDB_NOOVERWRITE : 0);
    if (rc == MDB_KEYEXIST) die(user, "already there - use set to replace");
    if (rc != 0) die_mdb("mdb_put", rc);
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0) die_mdb("mdb_txn_commit", rc);
  mdb_env_close(env);
  return 0;
}
