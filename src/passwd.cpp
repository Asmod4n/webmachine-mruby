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

namespace webmachine
{
namespace
{

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
    MDB_env *environment = nullptr;
    MDB_dbi sub_database = 0;
    // This worker's own read transaction, begun once and kept. A question
    // renews it and resets it after, so no reader slot is held between
    // questions and no begin is paid per login. MDB_NOTLS on the
    // environment is what lets the worker's thread own it.
    MDB_txn *read_txn = nullptr;
    // ad for argon2: the sub-database's name. Kept as a string because
    // argon2_ctx wants a pointer that outlives the call, and the record
    // itself carries none.
    std::string dbname;
};

// The environments a process opened, one per file, for the life of the
// process. Every Passwd points into this table and owns nothing of it.
struct SharedEnv {
    MDB_env *environment = nullptr;
    std::map<std::string, MDB_dbi> dbis;
};
std::mutex &shared_envs_mutex()
{
    static std::mutex lock;
    return lock;
}
std::map<std::string, SharedEnv> &shared_envs()
{
    static std::map<std::string, SharedEnv> table;
    return table;
}

void passwd_free(mrb_state *, void *raw)
{
    auto *passwd = static_cast<PasswdData *>(raw);
    if (passwd == nullptr)
        return;
    if (passwd->read_txn != nullptr)
        mdb_txn_abort(passwd->read_txn);
    delete passwd;
}

const struct mrb_data_type passwd_type = {"Webmachine::Passwd", passwd_free};

PasswdData *passwd_data_or_raise(mrb_state *mrb, mrb_value self)
{
    auto *passwd = static_cast<PasswdData *>(DATA_PTR(self));
    if (passwd == nullptr) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "this Webmachine::Passwd was never opened");
    }
    return passwd;
}

// One argon2id hash, run over whatever the caller gives it. Used both
// for a real check and for the dummy one a missing user still pays.
bool argon2id(const std::string &password, const uint8_t *salt, uint32_t salt_len,
              const std::string &associated_data, uint32_t m_kib, uint32_t passes, uint32_t lanes,
              uint8_t *out_hash, uint32_t out_len)
{
    argon2_context ctx{};
    ctx.out = out_hash;
    ctx.outlen = out_len;
    ctx.pwd = reinterpret_cast<uint8_t *>(const_cast<char *>(password.data()));
    ctx.pwdlen = static_cast<uint32_t>(password.size());
    ctx.salt = const_cast<uint8_t *>(salt);
    ctx.saltlen = salt_len;
    ctx.ad = reinterpret_cast<uint8_t *>(const_cast<char *>(associated_data.data()));
    ctx.adlen = static_cast<uint32_t>(associated_data.size());
    ctx.t_cost = passes;
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
void password_hash_a_dummy_record(const std::string &password, const std::string &associated_data)
{
    uint8_t salt[kDummySaltLen] = {};
    uint8_t dummy_hash[kDummyHashLen];
    (void)argon2id(password, salt, kDummySaltLen, associated_data, kDummyMKib, kDummyT, kDummyLanes,
                   dummy_hash, kDummyHashLen);
}

//: (String, String) -> Webmachine::Passwd
mrb_value passwd_open(mrb_state *mrb, mrb_value self)
{
    const char *file = nullptr;
    const char *dbname = nullptr;
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
    SharedEnv &shared = shared_envs()[path];
    int status = 0;
    if (shared.environment == nullptr) {
        MDB_env *environment = nullptr;
        status = mdb_env_create(&environment);
        if (status != 0) {
            mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): mdb_env_create: %s",
                       path.c_str(), mdb_strerror(status));
        }
        // A generous ceiling: webmachine-passwd's own default is 16, and
        // this side only reads, so a bigger number here costs nothing and
        // never refuses a file the tool made with more.
        mdb_env_set_maxdbs(environment, 128);
        status =
            mdb_env_open(environment, path.c_str(), MDB_RDONLY | MDB_NOSUBDIR | MDB_NOTLS, 0600);
        if (status != 0) {
            const std::string reason = mdb_strerror(status);
            mdb_env_close(environment);
            shared_envs().erase(path);
            mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): %s", path.c_str(),
                       reason.c_str());
        }
        shared.environment = environment;
    }
    MDB_env *const environment = shared.environment;

    MDB_dbi sub_database = 0;
    const auto known = shared.dbis.find(db);
    if (known != shared.dbis.end()) {
        sub_database = known->second;
    } else {
        MDB_txn *read_txn = nullptr;
        status = mdb_txn_begin(environment, nullptr, MDB_RDONLY, &read_txn);
        if (status != 0) {
            mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): mdb_txn_begin: %s",
                       path.c_str(), mdb_strerror(status));
        }
        // LMDB keeps a dbi handle private to the transaction that opened
        // it until that transaction commits; an aborted one closes the
        // handle right back, and every mdb_get through it would answer
        // EINVAL. So this transaction is committed, never aborted, even
        // though it reads.
        status = mdb_dbi_open(read_txn, db.c_str(), 0, &sub_database);
        if (status != 0) {
            mdb_txn_abort(read_txn);
        } else {
            status = mdb_txn_commit(read_txn);
        }
        if (status != 0) {
            mrb_raisef(mrb, E_WM_ERROR(mrb),
                       "Webmachine::Passwd.open(%s): no such sub-database %s: %s", path.c_str(),
                       db.c_str(), mdb_strerror(status));
        }
        shared.dbis[db] = sub_database;
    }

    MDB_txn *mine = nullptr;
    status = mdb_txn_begin(environment, nullptr, MDB_RDONLY, &mine);
    if (status != 0) {
        mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd.open(%s): mdb_txn_begin: %s",
                   path.c_str(), mdb_strerror(status));
    }
    // Reset at once: a reset transaction holds no reader slot, and the
    // first question renews it.
    mdb_txn_reset(mine);

    auto *passwd = new PasswdData();
    passwd->environment = environment;
    passwd->sub_database = sub_database;
    passwd->read_txn = mine;
    passwd->dbname = db;
    // self is the class here (open is a class method); the object it
    // hands back is a fresh instance, never self.
    const mrb_value handle = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_CDATA, mrb_class_ptr(self)));
    DATA_TYPE(handle) = &passwd_type;
    DATA_PTR(handle) = passwd;
    return handle;
}

// user.valid?(password) - answers true or false, never raises on a bad
// or missing record: an unknown user, a corrupt record and a wrong
// password all read the same way from the outside.
//: (String, String) -> bool
mrb_value passwd_valid(mrb_state *mrb, mrb_value self)
{
    PasswdData *const passwd = passwd_data_or_raise(mrb, self);
    const char *user = nullptr;
    const char *password = nullptr;
    mrb_int user_len = 0;
    mrb_int password_len = 0;
    mrb_get_args(mrb, "ss", &user, &user_len, &password, &password_len);
    const std::string pw(password, static_cast<size_t>(password_len));

    MDB_txn *const read_txn = passwd->read_txn;
    int status = mdb_txn_renew(read_txn);
    if (status != 0) {
        mrb_raisef(mrb, E_WM_ERROR(mrb), "Webmachine::Passwd#valid?: mdb_txn_renew: %s",
                   mdb_strerror(status));
    }
    MDB_val key{};
    key.mv_size = static_cast<size_t>(user_len);
    key.mv_data = const_cast<char *>(user);
    MDB_val val{};
    status = mdb_get(read_txn, passwd->sub_database, &key, &val);
    const bool found = status == 0;
    webmachine::PasswdRec header{};
    bool usable = false;
    const uint8_t *salt = nullptr;
    const uint8_t *hash = nullptr;
    if (found && val.mv_size >= sizeof header) {
        std::memcpy(&header, val.mv_data, sizeof header);
        const size_t want = sizeof header + header.salt_len + header.hash_len;
        if (header.version == webmachine::kPasswdRecVersion && header.salt_len > 0 &&
            header.salt_len <= kMaxSaltLen && header.hash_len > 0 &&
            header.hash_len <= kMaxHashLen && val.mv_size == want) {
            salt = static_cast<const uint8_t *>(val.mv_data) + sizeof header;
            hash = salt + header.salt_len;
            usable = true;
        }
    }
    mdb_txn_reset(read_txn);

    if (!usable) {
        // No user, or a record this side cannot read: the same cost is
        // paid either way, so the two cannot be told apart by the clock.
        password_hash_a_dummy_record(pw, passwd->dbname);
        return mrb_false_value();
    }

    uint8_t recomputed_hash[kMaxHashLen];
    if (!argon2id(pw, salt, header.salt_len, passwd->dbname, header.m_kib, header.t, header.lanes,
                  recomputed_hash, header.hash_len)) {
        return mrb_false_value();
    }
    const bool same = CRYPTO_memcmp(recomputed_hash, hash, header.hash_len) == 0;
    return mrb_bool_value(same);
}

} // namespace

void passwd_init_class(mrb_state *mrb, struct RClass *webmachine_module)
{
    struct RClass *const klass =
        mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(Passwd), mrb->object_class);
    MRB_SET_INSTANCE_TT(klass, MRB_TT_CDATA);
    mrb_undef_method_id(mrb, klass, MRB_SYM(initialize));
    mrb_define_class_method_id(mrb, klass, MRB_SYM(open), passwd_open, MRB_ARGS_REQ(2));
    mrb_define_method_id(mrb, klass, MRB_SYM_Q(valid), passwd_valid, MRB_ARGS_REQ(2));
}

} // namespace webmachine
