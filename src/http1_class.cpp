// The bodies of the Http1 members http1.hpp declares.
#include "http1.hpp"

namespace webmachine
{
void Http1::serve_docroot(const MimeDb *mime)
{
    mime_ = mime;
}

bool Http1::tunneled(const Conn &st) const
{
    if (st.ws != nullptr)
        return true;
    if (st.h2 == nullptr)
        return false;
    for (const H2Stream &s : st.h2->streams) {
        if (s.ws != nullptr)
            return true;
    }
    return false;
}

bool Http1::going_away(Conn &st, std::string &sink)
{
    if (st.ws == nullptr)
        return false;
    return ws_going_away(st.ws, sink);
}

bool Http1::timed(const Conn &st) const
{
    if (st.sse != nullptr)
        return true;
    if (st.h2 == nullptr)
        return false;
    for (const H2Stream &s : st.h2->streams) {
        if (s.sse != nullptr)
            return true;
    }
    return false;
}

void Http1::compute_task_refused(Conn &st, int park)
{
    Conn::Round *const r = st.park_at(park);
    if (r == nullptr)
        return;
    r->answer_ready = true;
    r->compute_task_full = true;
}

Http1::ComputeRefusal Http1::compute_task_refusal(Conn::Round &round)
{
    // A full pool is load, and load passes. The seconds move over 3..5
    // so a burst that was refused together does not come back together.
    if (round.compute_task_full) {
        static const char *const kWait[3] = {"Retry-After: 3\r\n", "Retry-After: 4\r\n",
                                             "Retry-After: 5\r\n"};
        static unsigned turn = 0;
        return {429, kWait[turn++ % 3]};
    }
    // The author's number was wrong. Coming back does not make the work
    // shorter, so nothing tells the client to.
    if (round.compute_task_over_deadline)
        return {500, {}};
    // The block or the arguments could not cross. Nothing a client does
    // changes that, so nothing tells it to come back.
    if (round.compute_task_not_crossed)
        return {500, {}};
    // A handle the worker needs is gone. A database that is restarted
    // comes back, and a minute is the size of that, not the seconds a
    // burst of load lives on.
    if (round.compute_task_raised)
        return {503, "Retry-After: 60\r\n"};
    return {};
}

bool Http1::watch_take(Conn &st, int *slot)
{
    if (st.w_pending.empty())
        return false;
    *slot = st.w_pending.back();
    st.w_pending.pop_back();
    return true;
}

std::string_view Http1::compute_task_user(const Conn &st, int park, int job)
{
    const Conn::Round *const r = st.park_at(park);
    if (r == nullptr || job < 0 || job >= Conn::kJobSlots)
        return {};
    return r->job.at(job).user_bytes;
}

bool Http1::compute_task_take(Conn &st, int park, int job, unsigned *code, std::string &bytes,
                              double *deadline)
{
    Conn::Round *const r = st.park_at(park);
    if (r == nullptr || job < 0 || job >= Conn::kJobSlots)
        return false;
    Conn::Round::Job &j = r->job.at(job);
    if (!j.waiting)
        return false;
    *code = j.code;
    *deadline = j.deadline;
    bytes.swap(j.bytes);
    j.bytes.clear();
    j.waiting = false;
    return true;
}

bool Http1::file_waiting(const Conn &st)
{
    return st.file != nullptr && st.file->stage == FileStage::kNamed;
}

bool Http1::compute_task_waiting(const Conn &st)
{
    return st.park_owes != 0;
}

uint8_t Http1::park_generation(const Conn &st, int park)
{
    return park >= 0 && park < Conn::kParkSlots ? st.park_gen[park] : 0;
}

bool Http1::park_take_pending(Conn &st, int *park)
{
    if (st.park_owes == 0)
        return false;
    const int slot = __builtin_ctz(st.park_owes);
    st.park_owes &= static_cast<uint16_t>(~(1u << slot));
    *park = slot;
    return true;
}

BodySpill *Http1::spill_waiting(Conn &st)
{
    if (st.spill.owes_write())
        return &st.spill;
    if (mrb_likely(st.h2 == nullptr))
        return nullptr;
    return spill_waiting_h2(st);
}

bool Http1::chunk_tchar(char c)
{
    const unsigned char u = static_cast<unsigned char>(c);
    return (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9') || c == '!' ||
           c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
           c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

bool Http1::chunk_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

__attribute__((noinline)) bool Http1::chunk_size_line_ok(const char *p, size_t n)
{
    size_t i = 0;
    while (i < n && chunk_hex(p[i]))
        i++;
    if (i == 0)
        return false;

    while (i < n) {
        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
        if (i >= n || p[i] != ';')
            return false;
        i++;
        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
        const size_t name = i;
        while (i < n && chunk_tchar(p[i]))
            i++;
        if (i == name)
            return false;
        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
        if (i >= n || p[i] != '=')
            continue;
        i++;
        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
        if (i < n && p[i] == '"') {
            i++;
            bool closed = false;
            while (i < n) {
                if (p[i] == '\\' && i + 1 < n) {
                    i += 2;
                    continue;
                }
                if (p[i] == '"') {
                    i++;
                    closed = true;
                    break;
                }
                i++;
            }
            if (!closed)
                return false;
        } else {
            const size_t val = i;
            while (i < n && chunk_tchar(p[i]))
                i++;
            if (i == val)
                return false;
        }
    }
    return true;
}

__attribute__((noinline)) bool Http1::chunk_lines_ok(Conn &st, const char *data, size_t len)
{
    size_t i = 0;
    while (i < len) {
        if (st.chunk_scan == Conn::ChunkScan::kDone)
            return true;

        if (st.chunk_scan == Conn::ChunkScan::kData) {
            const size_t take = len - i < st.chunk_need ? len - i : st.chunk_need;
            i += take;
            st.chunk_need -= take;
            if (st.chunk_need == 0)
                st.chunk_scan = Conn::ChunkScan::kAfterData;
            continue;
        }

        if (st.chunk_scan == Conn::ChunkScan::kAfterData) {
            // RFC 9112 7.1: the CRLF that closes a chunk, and nothing else.
            const char want = st.chunk_after == 0 ? '\r' : '\n';
            if (data[i] != want)
                return false;
            i++;
            st.chunk_after++;
            if (st.chunk_after == 2) {
                st.chunk_after = 0;
                st.chunk_scan = Conn::ChunkScan::kSize;
            }
            continue;
        }

        // kSize: gather to the CRLF, then hold the line to the grammar.
        const char *const nl = static_cast<const char *>(std::memchr(data + i, '\n', len - i));
        if (nl == nullptr) {
            // The line runs past this buffer. A size line this long is not a
            // size line; kMaxHead is far more room than the grammar needs.
            if (st.chunk_line.size() + (len - i) > kMaxHead)
                return false;

            st.chunk_line.append(data + i, len - i);
            return true;
        }
        const size_t upto = static_cast<size_t>(nl - (data + i));
        if (st.chunk_line.size() + upto > kMaxHead)
            return false;

        st.chunk_line.append(data + i, upto);
        i += upto + 1;
        // The CR belongs to the terminator, never to the line.
        if (st.chunk_line.empty() || st.chunk_line.back() != '\r')
            return false;

        st.chunk_line.pop_back();
        if (!chunk_size_line_ok(st.chunk_line.data(), st.chunk_line.size()))
            return false;

        size_t size = 0;
        for (char c : st.chunk_line) {
            if (!chunk_hex(c))
                break;
            const unsigned d = c <= '9' ? static_cast<unsigned>(c - '0')
                                        : static_cast<unsigned>((c | 0x20) - 'a') + 10;
            // A size that cannot be held is a size this server will not read.
            if (size > (SIZE_MAX - d) / 16)
                return false;

            size = size * 16 + d;
        }
        st.chunk_line.clear();
        if (size == 0) {
            // RFC 9112 7.1.2: the trailer section follows, and the decoder
            // reads it. Its field rules are not this walk's business.
            st.chunk_scan = Conn::ChunkScan::kDone;
            return true;
        }
        st.chunk_need = size;
        st.chunk_scan = Conn::ChunkScan::kData;
    }
    return true;
}

__attribute__((noinline)) void Http1::drop_body(Conn &st)
{
    st.body_to = Conn::Body::kNone;
    st.content_need = 0;
    st.body_hold.clear();
    st.spill.close_file();
    st.run_wants_body = false;
}

bool Http1::file_answerable(const Conn &st)
{
    return st.file != nullptr &&
           (st.file->stage == FileStage::kDeliver || st.file->stage == FileStage::kDone);
}

bool Http1::run_resumable(const Conn &st)
{
    if (mrb_likely(!st.run_parked()))
        return false;
    const Conn::Round *const r = st.park_at(st.parked.co.promise().park);
    return r != nullptr && r->answer_ready;
}

size_t Http1::file_map_len(const Conn &st)
{
    return (st.file != nullptr && st.file->map_wanted) ? st.file->content_length : 0;
}

Http1::AnswerStep Http1::answer_step(const AnswerFacts &f)
{
    AnswerStep s;
    s.body_len = f.has_lent ? f.lent_len : f.body_len;
    s.answered = f.answered_already;
    if (f.have_body && f.status == 200) {
        s.shape = f.has_lent ? AnswerStep::Shape::kLent
                             : (f.gzip_ok ? AnswerStep::Shape::kGzip : AnswerStep::Shape::kPlain);
        s.answered = true;
    } else if (f.answered_already) {
        s.shape = AnswerStep::Shape::kAlready;
    } else if (f.status == 500 && f.bound) {
        // Whether a body exists is a question for the VM, so the caller
        // demotes this to kStatus when the answer is no.
        s.shape = AnswerStep::Shape::kException;
    } else {
        s.shape = AnswerStep::Shape::kStatus;
    }
    return s;
}

Http1::H2SendStep Http1::h2_send_step(const H2Stream &s, RoundRoom room)
{
    const int64_t conn_window = room.conn_window;
    const size_t chunk = room.chunk;
    H2SendStep o;
    if (!s.response_content.owes())
        return o;
    o.start = s.response_content.sent;
    o.total = s.response_content.length;
    size_t remaining = s.response_content.length - s.response_content.sent;
    // A copied buffer is bounded per round; a lend and a mapping are not.
    if (s.response_content.src == H2Stream::Content::Src::kOwned && remaining > chunk) {
        remaining = chunk;
    }
    const int64_t budget = conn_window < s.flow_window ? conn_window : s.flow_window;
    if (budget <= 0)
        return o; // owed, but the window is shut: give stays 0
    o.give = remaining;
    if (static_cast<int64_t>(o.give) > budget)
        o.give = static_cast<size_t>(budget);
    o.ends = o.give != 0 && o.start + o.give == o.total;
    return o;
}

Http1::AssetStep Http1::asset_step(const AssetEntry &e, const RangeAsk &ask)
{
    const uint16_t verdict = ask.verdict;
    const bool head_only = ask.head_only;
    const http::ReqValues &vals = ask.vals;
    AssetStep s;
    s.status_code = verdict;
    if (verdict == 412 || verdict == 501) {
        s.head = AssetStep::HeadKind::kRefusal;
        return s;
    }
    const size_t complete_length = Assets::wire_len(e);
    if (verdict == 200 && !head_only && ask.method == flow::Method::kGet && vals.range != nullptr &&
        (vals.if_range == nullptr ||
         http::if_range_matches({vals.if_range, vals.if_range_len}, {e.etag, sizeof(e.etag)}))) {
        http::ByteRange r = {0, 0};
        switch (http::parse_range({{vals.range, vals.range_len}, complete_length}, r)) {
            case http::RangeParse::kOne:
                s.head = AssetStep::HeadKind::kRange;
                s.status_code = 206;
                s.first_byte_pos = r.first;
                s.content_length = r.last - r.first + 1;
                s.sends_content = true;
                break;
            case http::RangeParse::kUnsat:
                s.head = AssetStep::HeadKind::kUnsatisfiable;
                s.status_code = 416;
                return s;
            case http::RangeParse::kNone:
                break;
        }
    }
    if (s.head == AssetStep::HeadKind::kNormal && verdict == 200 && !head_only) {
        s.content_length = complete_length;
        s.sends_content = true;
    }
    return s;
}

FileStep Http1::file_step(const Conn::FileXfer &x, size_t chunk)
{
    FileStep s;
    s.persist = x.persist;
    s.sent_after = x.content_sent;
    s.next = x.stage;
    switch (x.stage) {
        case FileStage::kDeliver: {
            const bool mapped = x.map_addr != nullptr;
            const size_t left =
                x.content_length > x.content_sent ? x.content_length - x.content_sent : 0;
            // A mapping lends a bounded chunk of itself; a window lends exactly
            // what the read put in it.
            const size_t take = mapped ? (left < chunk ? left : chunk) : x.buf_filled;
            s.head = !x.head.empty();
            if (take != 0) {
                s.src = mapped ? FileStep::Src::kMapping : FileStep::Src::kWindow;
                // A mapping is walked from where the transfer stands; the window
                // buffer holds only this round's bytes and starts at zero.
                s.start = mapped ? x.content_sent : 0;
            }
            s.give = take;
            s.sent_after = x.content_sent + take;
            // A window is refilled by the ring, so the next round waits on it.
            // A mapping has no read coming to wake it and drives itself.
            s.next = s.sent_after < x.content_length
                         ? (mapped ? FileStage::kDeliver : FileStage::kRing)
                         : FileStage::kDone;
            break;
        }
        case FileStage::kDone:
            // The last lend has drained - that is what kDone means and the only
            // way to reach it. So this is where the mapping goes back and where
            // the transfer's one access line is owed.
            s.release_map = x.map_addr != nullptr;
            s.log = true;
            s.clear = true;
            s.next = FileStage::kNone;
            break;
        default:
            break;
    }
    return s;
}

void Http1::file_release(Conn &st)
{
    if (st.file != nullptr && st.file->buf.capacity() > kDeliverChunk) {
        std::string().swap(st.file->buf);
    }
}

Logger *Http1::access_log()
{
    return &alog_;
}

void Http1::enable_access_log()
{
    alog_.enabled = true;
}

Logger *Http1::error_log()
{
    return &elog_;
}

void Http1::enable_error_log()
{
    elog_.enabled = true;
}

void Http1::set_zero_copy_threshold(size_t n)
{
    zc_min_ = n;
}

void Http1::set_file_map_threshold(size_t n)
{
    map_min_ = n;
}

void Http1::set_send_timeout(int secs)
{
    send_chunk_ = file_send_chunk(secs);
}

const Http1::Variants &Http1::variants(uint16_t status) const
{
    return store_[index_[status]];
}

const Http1::Variants &Http1::prefixes(uint16_t status) const
{
    return store_prefix_[index_[status]];
}

Http1::AnswerStep Http1::spell_answer(Round &r, Spelling sp)
{
    Conn &st = r.st;
    const Bundle *const b = r.b;
    const int minor = r.minor;
    const bool persist = r.persist;
    const bool head_only = r.head_only;
    const http::ReqValues &vals = r.vals;
    const char *const method = r.method;
    const size_t method_len = r.method_len;
    const char *const path = r.path;
    const size_t path_len = r.path_len;
    std::string &sink = sp.sink;
    Plan *const plan = sp.plan;
    const uint16_t status = sp.status;
    const char *const lent = sp.lent;
    const size_t lent_len = sp.lent_len;
    const bool answered = sp.answered;
    const bool have_body = sp.have_body;
    const bool accept_gzip = sp.accept_gzip;
    const std::array<uint16_t, 600> *const idx = sp.idx;
    AnswerStep astep =
        answer_step({status, sp.body.size(), lent_len, answered, have_body, lent != nullptr,
                     b != nullptr && b->gzip_ok, b != nullptr && b->bound});
    mrb_value exc_value = mrb_nil_value();
    // #210: what led here, gathered once - the record and the page carry
    // the same hash because they are taken over the same facts.
    ErrFacts ef;
    std::string ef_backtrace;
    std::string ef_steering;
    char ef_hash[kFingerprintLen] = {};
    if (mrb_unlikely(astep.shape == AnswerStep::Shape::kException)) {
        ef.peer = st.peer;
        ef.peer_len = st.peer_len;
        ef.request_target = path;
        ef.request_target_len = path_len;
        ef.method = method;
        ef.method_len = method_len;
        spell_steering(&vals, ef_steering);
        ef.steering = ef_steering.data();
        ef.steering_len = ef_steering.size();
        // The request as the resource saw it: lent for this frame, which is
        // the frame still being answered.
        ef.body = b->res->run.req != nullptr ? b->res->run.req->content : nullptr;
        ef.body_len = b->res->run.req != nullptr ? b->res->run.req->content_len : 0;
        ef.body_full = ef.body_len;
        ef.status_code = 500;
        exception_facts(b->res->mrb, {ef, ef_backtrace});
        spell_fingerprint(ef_hash, fingerprint_of(ef));
        if (elog_.enabled)
            log_error(elog_, ef);
        // #210: handle_exception lives on the error resource and nowhere
        // else, so the exception object itself is what crosses over - not
        // a message some resource already made of it.
        if (resource_exception_take(*b->res, &exc_value))
            astep.answered = true;
        else
            astep.shape = AnswerStep::Shape::kStatus;
    }
    switch (astep.shape) {
        case AnswerStep::Shape::kAlready:
            break;
        case AnswerStep::Shape::kLent: {
            const Variants &pv = b->gzip_ok ? b->ok_prefix_vary : b->ok_prefix;
            const Resp &pfx =
                minor >= 1 ? (persist ? pv.plain : pv.close) : (persist ? pv.keep : pv.close);
            sink.append(pfx.bytes);
            char cl[40];
            sink.append(cl, http::spell_content_length(cl, lent_len));
            body_lend(st, sink, {{lent, lent_len}, *plan});
            break;
        }
        case AnswerStep::Shape::kGzip: {
            const Resp &prefix_id =
                minor >= 1 ? (persist ? b->ok_prefix_vary.plain : b->ok_prefix_vary.close)
                           : (persist ? b->ok_prefix_vary.keep : b->ok_prefix_vary.close);
            const Resp &prefix_gz =
                minor >= 1 ? (persist ? b->ok_prefix_gzip.plain : b->ok_prefix_gzip.close)
                           : (persist ? b->ok_prefix_gzip.keep : b->ok_prefix_gzip.close);
            assemble_dynamic(
                {prefix_id, prefix_gz, sp.body, accept_gzip && st.packetized, head_only}, sink);
            break;
        }
        case AnswerStep::Shape::kPlain: {
            const Resp &prefix = minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                            : (persist ? b->ok_prefix.keep : b->ok_prefix.close);
            answer_assemble(sink, {prefix, sp.body, head_only});
            break;
        }
        case AnswerStep::Shape::kException: {
            std::string message;
            err_pages_.exception_text(exc_value, message);
            const Variants &pv = store_prefix_[(*idx)[500]];
            const Variants &bv = store_[(*idx)[500]];
            ErrorPages::Fields f;
            f.message = message.data();
            f.message_len = message.size();
            f.fingerprint = ef_hash;
            // A ship build says what was thrown and where the log has the rest; a
            // debug build is already telling you about itself, so the trace goes
            // on the page too.
            if (kDebugBuild) {
                f.backtrace = ef.backtrace;
                f.backtrace_len = ef.backtrace_len;
            }
            const Resp &prefix =
                minor >= 1 ? (persist ? pv.plain : pv.close) : (persist ? pv.keep : pv.close);
            const Resp &bodyless =
                minor >= 1 ? (persist ? bv.plain : bv.close) : (persist ? bv.keep : bv.close);
            spell_error({prefix, bodyless, 500,
                         err_pages_.media_pick_for_status(500, vals.accept, vals.accept_len), f,
                         head_only},
                        sink);
            break;
        }
        case AnswerStep::Shape::kStatus: {
            const Variants &sv = (head_only && status == 200) ? b->ok_head : store_[(*idx)[status]];
            const Resp &bodyless =
                minor >= 1 ? (persist ? sv.plain : sv.close) : (persist ? sv.keep : sv.close);
            // RFC 9110 15: only a 4xx or 5xx has something to explain. A 204,
            // a 304 or a redirect is an answer, and answers carry no page.
            if (status >= 400) {
                const Variants &pv = store_prefix_[(*idx)[status]];
                const ErrorPages::Fields f;
                const Resp &prefix =
                    minor >= 1 ? (persist ? pv.plain : pv.close) : (persist ? pv.keep : pv.close);
                spell_error({prefix, bodyless, status,
                             err_pages_.media_pick_for_status(status, vals.accept, vals.accept_len),
                             f, head_only},
                            sink);
            } else if (status == 200 && !head_only && plan != nullptr &&
                       b->konst.body.size() >= kLendFloor) {
                // The konst body is a std::string built at setup and immortal.
                // Nothing for the GC to move or collect, so it is lent as a
                // pointer rather than copied into this connection's sink - a
                // copy gives every stalled reader a private duplicate of the
                // same answer.
                //
                // From kLendFloor up. Below it the whole prebuilt 200 goes into
                // the sink - head, Content-Length and body in one piece - and
                // the round leaves as one send.
                const Resp &pfx = minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                             : (persist ? b->ok_prefix.keep : b->ok_prefix.close);
                sink.append(pfx.bytes);
                char cl[40];
                sink.append(cl, http::spell_content_length(cl, b->konst.body.size()));
                body_lend(st, sink, {{b->konst.body.data(), b->konst.body.size()}, *plan});
            } else {
                sink.append(bodyless.bytes);
            }
            break;
        }
    }
    return astep;
}

bool Http1::h2_can_stop(const Bundle *b)
{
    return b != nullptr && b->bound && b->res != nullptr &&
           ((b->res->compute | b->res->watch) != 0 ||
            (b->res->value_jobs | b->res->value_watch) != 0);
}

} // namespace webmachine
