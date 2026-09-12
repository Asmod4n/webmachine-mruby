//
// Webmachine::Passwd - the database webmachine-passwd writes, read for
// one question a resource asks: is this password right for this user.
//
// The layout is read here, in C++, beside PasswdRec (src/webmachine.hpp)
// - never in Ruby by byte arithmetic. Ruby only calls valid?; the record
// itself never crosses into a VM.
//
// One object is meant to live for the life of a worker, built once
// through Webmachine::Workers::Registry (#80). The LMDB environment
// behind it is one per file per process, shared by every worker: LMDB
// refuses a file opened twice in one process, and that is what a
// per-worker open did, and why the first bintest of this file hung.
#include "http1.hpp"

#include <map>
#include <mutex>
#include <string>

#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <lmdb.h>
#include <argon2.h>
#include <openssl/crypto.h>

#include <cstring>
#include <string>

namespace webmachine {
namespace {

// The default cost webmachine-passwd picks with no --time given
// (tools/webmachine-passwd/main.cpp, kCosts[kDefaultCost]). A missing
// user still pays this, over a record that never verifies, so a user
// list cannot be read off the clock.
constexpr uint32_t kDummyMKib = 19456;
constexpr uint32_t kDummyT = 2;
constexpr uint32_t kDummyLanes = 1;
constexpr uint8_t kDummySaltLen = 16;
constexpr uint8_t kDummyHashLen = 32;

// A record this large or larger is not a record webmachine-passwd ever
// wrote. Bounded so a corrupt or hostile file cannot ask argon2 for an
// unbounded salt or hash.
constexpr size_t kMaxSaltLen = 64;
constexpr size_t kMaxHashLen = 64;

struct PasswdData {
  MDB_env* env = nullptr;
  MDB_dbi dbi = 0;
  // This worker's own read transaction, begun once and kept. A question
  // renews it and resets it after, so no reader slot is held between
  // questions and no begin is paid per login. MDB_NOTLS on the
  // environment is what lets the worker's thread own it.
  MDB_txn* txn = nullptr;
  // ad for argon2: the sub-database's name. Kept as a string because
  // argon2_ctx wants a pointer that outlives the call, and the record
  // itself carries none.
  std::string dbname;
};

// The environments a process opened, one per file, for the life of the
// process. Every Passwd points into this table and owns nothing of it.
struct SharedEnv {
  MDB_env* env = nullptr;
  std::map<std::string, MDB_dbi> dbis;
};
std::mutex& shared_envs_mutex() {
  static std::mutex m;
  return m;
}
std::map<std::string, SharedEnv>& shared_envs() {
  static std::map<std::string, SharedEnv> table;
  return table;
}

void passwd_free(mrb_state*, void* p) {
  auto* d = static_cast<PasswdData*>(p);
  if (d == nullptr) return;
  if (d->txn != nullptr) mdb_txn_abort(d->txn);
  delete d;
}

const struct mrb_data_type passwd_type = {"Webmachine::Passwd", passwd_free};

PasswdData* live(mrb_state* mrb, mrb_value self) {
  auto* d = static_cast<PasswdData*>(DATA_PTR(self));
  if (d == nullptr) {
    mrb_raise(mrb, E_WM_ERROR(mrb), "this Webmachine::Passwd was never opened");
  }
  return d;
}

// One argon2id hash, run over whatever the caller gives it. Used both
// for a real check and for the dummy one a missing user still pays.
bool argon2id(const std::string& password, const uint8_t* salt, uint32_t salt_len,
             const std::string& ad, uint32_t m_kib, uint32_t t, uint32_t lanes,
             uint8_t* out, uint32_t out_len) {
  argon2_context ctx {};
  ctx.out = out;
  ctx.outlen = out_len;
  ctx.pwd = reinterpret_cast<uint8_t*>(const_cast<char*>(password.data()));
  ctx.pwdlen = static_cast<uint32_t>(password.size());
  ctx.salt = const_cast<uint8_t*>(salt);
  ctx.saltlen = salt_len;
  ctx.ad = reinterpret_cast<uint8_t*>(const_cast<char*>(ad.data()));
  ctx.adlen = static_cast<uint32_t>(ad.size());
  ctx.t_cost = t;
  ctx.m_cost = m_kib;
  ctx.lanes = lanes;
  ctx.threads = lanes;
  ctx.version = ARGON2_VERSION_NUMBER;
  ctx.flags = ARGON2_DEFAULT_FLAGS;
  return argon2_ctx(&ctx, Argon2_id) == ARGON2_OK;
}

// The check a missing user still pays, so the time an answer takes
// never names who is in the database. Same cost the tool defaults to,
// a fixed salt (never written anywhere, and never compared against
// anything), and an answer nobody looks at.
void pay_dummy_cost(const std::string& password, const std::string& ad) {
  uint8_t salt[kDummySaltLen] = {};
  uint8_t out[kDummyHashLen];
  (void)argon2id(password, salt, kDummySaltLen, ad, kDummyMKib, kDummyT, kDummyLanes, out,
                kDummyHashLen);
}

//: (String, String) -> Webmachine::Passwd
mrb_value passwd_open(mrb_state* mrb, mrb_value self) {
  const char* file = nullptr;
  const char* dbname = nullptr;
  mrb_int file_len = 0;
  mrb_int dbname_len = 0;
  mrb_get_args(mrb, "ss", &file, &file_len, &dbname, &dbname_len);
  const std::string path(file, static_cast<size_t>(file_len));
  const std::string db(dbname, static_cast<size_t>(dbname_len));

  // LMDB allows one environment per file per process: a second
  // mdb_env_open of the same file from the same process is what its
  // manual forbids, and it is what a per-worker open would do. So the
  // environment is shared by every Passwd of this process, opened on
  // the first call and never closed, and each call only adds the
  // sub-database it names. MDB_NOTLS keeps a read transaction off the
  // thread's identity, so every worker begins and ends its own.
  std::lock_guard<std::mutex> hold(shared_envs_mutex());
  SharedEnv& shared = shared_envs()[path];
  int rc = 0;
  if (shared.env == nullptr) {
    MDB_env* env = nullptr;
    rc = mdb_env_create(&env);
    if (rc != 0) {
      mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): mdb_env_create: %s",
                path.c_str(), mdb_strerror(rc));
    }
    // A generous ceiling: webmachine-passwd's own default is 16, and
    // this side only reads, so a bigger number here costs nothing and
    // never refuses a file the tool made with more.
    mdb_env_set_maxdbs(env, 128);
    rc = mdb_env_open(env, path.c_str(), MDB_RDONLY | MDB_NOSUBDIR | MDB_NOTLS, 0600);
    if (rc != 0) {
      const std::string why = mdb_strerror(rc);
      mdb_env_close(env);
      shared_envs().erase(path);
      mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): %s", path.c_str(),
                why.c_str());
    }
    shared.env = env;
  }
  MDB_env* const env = shared.env;

  MDB_dbi dbi = 0;
  const auto known = shared.dbis.find(db);
  if (known != shared.dbis.end()) {
    dbi = known->second;
  } else {
    MDB_txn* txn = nullptr;
    rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) {
      mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): mdb_txn_begin: %s",
                path.c_str(), mdb_strerror(rc));
    }
    // LMDB keeps a dbi handle private to the transaction that opened
    // it until that transaction commits; an aborted one closes the
    // handle right back, and every mdb_get through it would answer
    // EINVAL. So this transaction is committed, never aborted, even
    // though it reads.
    rc = mdb_dbi_open(txn, db.c_str(), 0, &dbi);
    if (rc != 0) {
      mdb_txn_abort(txn);
    } else {
      rc = mdb_txn_commit(txn);
    }
    if (rc != 0) {
      mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): no such sub-database %s: %s",
                path.c_str(), db.c_str(), mdb_strerror(rc));
    }
    shared.dbis[db] = dbi;
  }

  MDB_txn* mine = nullptr;
  rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &mine);
  if (rc != 0) {
    mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): mdb_txn_begin: %s",
              path.c_str(), mdb_strerror(rc));
  }
  // Reset at once: a reset transaction holds no reader slot, and the
  // first question renews it.
  mdb_txn_reset(mine);

  auto* d = new PasswdData();
  d->env = env;
  d->dbi = dbi;
  d->txn = mine;
  d->dbname = db;
  // self is the class here (open is a class method); the object it
  // hands back is a fresh instance, never self.
  const mrb_value out = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_CDATA, mrb_class_ptr(self)));
  DATA_TYPE(out) = &passwd_type;
  DATA_PTR(out) = d;
  return out;
}

// user.valid?(password) - answers true or false, never raises on a bad
// or missing record: an unknown user, a corrupt record and a wrong
// password all read the same way from the outside.
//: (String, String) -> bool
mrb_value passwd_valid(mrb_state* mrb, mrb_value self) {
  PasswdData* const d = live(mrb, self);
  const char* user = nullptr;
  const char* password = nullptr;
  mrb_int user_len = 0;
  mrb_int password_len = 0;
  mrb_get_args(mrb, "ss", &user, &user_len, &password, &password_len);
  const std::string pw(password, static_cast<size_t>(password_len));

  MDB_txn* const txn = d->txn;
  int rc = mdb_txn_renew(txn);
  if (rc != 0) {
    mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd#valid?: mdb_txn_renew: %s", mdb_strerror(rc));
  }
  MDB_val key {};
  key.mv_size = static_cast<size_t>(user_len);
  key.mv_data = const_cast<char*>(user);
  MDB_val val {};
  rc = mdb_get(txn, d->dbi, &key, &val);
  const bool found = rc == 0;
  webmachine::PasswdRec rec {};
  bool usable = false;
  const uint8_t* salt = nullptr;
  const uint8_t* hash = nullptr;
  if (found && val.mv_size >= sizeof rec) {
    std::memcpy(&rec, val.mv_data, sizeof rec);
    const size_t want = sizeof rec + rec.salt_len + rec.hash_len;
    if (rec.version == webmachine::kPasswdRecVersion && rec.salt_len > 0 &&
        rec.salt_len <= kMaxSaltLen && rec.hash_len > 0 && rec.hash_len <= kMaxHashLen &&
        val.mv_size == want) {
      salt = static_cast<const uint8_t*>(val.mv_data) + sizeof rec;
      hash = salt + rec.salt_len;
      usable = true;
    }
  }
  mdb_txn_reset(txn);

  if (!usable) {
    // No user, or a record this side cannot read: the same cost is
    // paid either way, so the two cannot be told apart by the clock.
    pay_dummy_cost(pw, d->dbname);
    return mrb_false_value();
  }

  uint8_t out[kMaxHashLen];
  if (!argon2id(pw, salt, rec.salt_len, d->dbname, rec.m_kib, rec.t, rec.lanes, out,
               rec.hash_len)) {
    return mrb_false_value();
  }
  const bool same = CRYPTO_memcmp(out, hash, rec.hash_len) == 0;
  return mrb_bool_value(same);
}

}  // namespace

void passwd_init_class(mrb_state* mrb, struct RClass* wm) {
  struct RClass* const klass =
      mrb_define_class_under_id(mrb, wm, MRB_SYM(Passwd), mrb->object_class);
  MRB_SET_INSTANCE_TT(klass, MRB_TT_CDATA);
  mrb_undef_method_id(mrb, klass, MRB_SYM(initialize));
  mrb_define_class_method_id(mrb, klass, MRB_SYM(open), passwd_open, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, klass, MRB_SYM_Q(valid), passwd_valid, MRB_ARGS_REQ(2));
}

}  // namespace webmachine
