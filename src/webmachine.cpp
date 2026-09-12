// The bodies of what webmachine.hpp declares.
#include "webmachine.hpp"

namespace webmachine
{
struct io_uring_sqe *sqe_or_raise(mrb_state *mrb, struct io_uring *ring)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe != nullptr)
        return sqe;
    io_uring_submit(ring);
    sqe = io_uring_get_sqe(ring);
    if (sqe == nullptr)
        mrb_raise(mrb, E_WM_ERROR(mrb), "the submission queue is full");
    return sqe;
}

mrb_state *open_vm_or_say(const char *who)
{
    mrb_state *const mrb = mrb_open();
    if (mrb == nullptr) {
        std::fprintf(stderr, "%s: mrb_open failed\n", who);
        return nullptr;
    }
    if (mrb->exc != nullptr) {
        std::fprintf(stderr, "%s: a gem init raised\n", who);
        mrb_print_error(mrb);
        mrb_close(mrb);
        return nullptr;
    }
    return mrb;
}

bool log_queue_full(Logger &logger)
{
    if (logger.pending.size() > kLogQueueCap) {
        logger.dropped++;
        return true;
    }
    if (logger.dropped != 0) {
        std::fprintf(stderr, "webmachine: the log fell behind - %zu records dropped\n",
                     logger.dropped);
        logger.dropped = 0;
    }
    return false;
}

void log_access(Logger &logger, const AccessLine &line)
{
    if (mrb_unlikely(log_queue_full(logger)))
        return;
    size_t peer_len = line.peer.size();
    size_t method_token_len = line.method_token.size();
    size_t request_target_len = line.request_target.size();
    size_t referer_len = line.referer.size();
    size_t user_agent_len = line.user_agent.size();
    const uint8_t flags = line.flags;
    const uint16_t status_code = line.status_code;
    const size_t content_length = line.content_length;
    const char *peer = line.peer.data();
    const char *method_token = line.method_token.data();
    const char *request_target = line.request_target.data();
    const char *referer = line.referer.data();
    const char *user_agent = line.user_agent.data();
    if (method_token_len > 255)
        method_token_len = 255;
    if (peer_len > 255)
        peer_len = 255;
    if (request_target_len > 65535)
        request_target_len = 65535;
    if (referer_len > 65535)
        referer_len = 65535;
    if (user_agent_len > 65535)
        user_agent_len = 65535;
    LogRec round;
    round.version = kLogRecVersion;
    round.flags = flags;
    round.status_code = status_code;
    round.content_length =
        content_length > 0xffffffffull ? 0xffffffffu : static_cast<uint32_t>(content_length);
    round.unix_seconds = logger.unix_seconds;
    round.method_token_len = static_cast<uint8_t>(method_token_len);
    round.peer_len = static_cast<uint8_t>(peer_len);
    round.request_target_len = static_cast<uint16_t>(request_target_len);
    round.referer_len = static_cast<uint16_t>(referer_len);
    round.user_agent_len = static_cast<uint16_t>(user_agent_len);
    logger.pending.append(reinterpret_cast<const char *>(&round), sizeof round);
    if (method_token_len != 0)
        logger.pending.append(method_token, method_token_len);
    if (peer_len != 0)
        logger.pending.append(peer, peer_len);
    if (request_target_len != 0)
        logger.pending.append(request_target, request_target_len);
    if (referer_len != 0)
        logger.pending.append(referer, referer_len);
    if (user_agent_len != 0)
        logger.pending.append(user_agent, user_agent_len);
}

uint64_t &app_build_hash()
{
    static uint64_t h = 0;
    return h;
}

uint64_t fnv1a(uint64_t headers, const void *bytes, size_t count)
{
    const unsigned char *block = static_cast<const unsigned char *>(bytes);
    size_t i = 0;
    for (; i < count; i++) {
        headers ^= block[i];
        headers *= 0x100000001b3ULL;
    }
    return headers;
}

uint64_t fnv1a_piece(uint64_t headers, const void *bytes, size_t count)
{
    const uint32_t length = static_cast<uint32_t>(count);
    headers = fnv1a(headers, &length, sizeof length);
    return count != 0 ? fnv1a(headers, bytes, count) : headers;
}

void spell_fingerprint(char *out_value, uint64_t headers)
{
    static const char kHex[] = "0123456789abcdef";
    size_t i = 0;
    for (; i < kFingerprintLen; i++)
        out_value[i] = kHex[(headers >> ((15 - i) * 4)) & 0xf];
}

uint64_t fingerprint_of(const ErrFacts &field)
{
    uint64_t headers = app_build_hash();
    headers = fnv1a_piece(headers, field.method, field.method_len);
    headers = fnv1a_piece(headers, field.request_target, field.request_target_len);
    headers = fnv1a_piece(headers, field.steering, field.steering_len);
    headers = fnv1a_piece(headers, field.exception_class, field.exception_class_len);
    headers = fnv1a_piece(headers, field.backtrace, field.backtrace_len);
    headers = fnv1a_piece(headers, &field.status_code, sizeof field.status_code);
    return headers;
}

void log_error(Logger &logger, const ErrFacts &field)
{
    if (mrb_unlikely(log_queue_full(logger)))
        return;
    // A 4xx is an answer, not a failure: the client asked for something it
    // may not have, and the server said so. Nothing raised, so there is
    // nothing to explain and no hash to hand out. Refused here, once, so no
    // call site has to remember it.
    if (field.status_code >= 400 && field.status_code < 500)
        return;
    const size_t peer_len = field.peer_len > 255 ? 255 : field.peer_len;
    const size_t class_len = field.exception_class_len > 255 ? 255 : field.exception_class_len;
    const size_t target_len = field.request_target_len > 65535 ? 65535 : field.request_target_len;
    const size_t message_len = field.message_len > 65535 ? 65535 : field.message_len;
    const size_t backtrace_len = field.backtrace_len > 65535 ? 65535 : field.backtrace_len;
    const size_t method_len = field.method_len > 255 ? 255 : field.method_len;
    const size_t steering_len = field.steering_len > 255 ? 255 : field.steering_len;
    const size_t body_len = field.body_len > kBodyKept ? kBodyKept : field.body_len;
    ErrRec round;
    round.version = kErrRecVersion;
    round.flags = 0; // no RFC, and nothing sets it yet: reserved on the wire
    round.status_code = field.status_code;
    round.unix_seconds = logger.unix_seconds;
    round.peer_len = static_cast<uint8_t>(peer_len);
    round.exception_class_len = static_cast<uint8_t>(class_len);
    round.request_target_len = static_cast<uint16_t>(target_len);
    round.message_len = static_cast<uint16_t>(message_len);
    round.backtrace_len = static_cast<uint16_t>(backtrace_len);
    round.method_len = static_cast<uint8_t>(method_len);
    round.steering_len = static_cast<uint8_t>(steering_len);
    round.body_len = static_cast<uint16_t>(body_len);
    round.body_full_len = static_cast<uint32_t>(field.body_full);
    spell_fingerprint(round.fingerprint, fingerprint_of(field));
    spell_fingerprint(round.app_build, app_build_hash());
    round.dynamic_len = static_cast<uint32_t>(peer_len + class_len + target_len + message_len +
                                              backtrace_len + method_len + steering_len + body_len);
    logger.pending.append(reinterpret_cast<const char *>(&round), sizeof round);
    if (peer_len != 0)
        logger.pending.append(static_cast<const char *>(field.peer), peer_len);
    if (class_len != 0)
        logger.pending.append(field.exception_class, class_len);
    if (target_len != 0)
        logger.pending.append(field.request_target, target_len);
    if (message_len != 0)
        logger.pending.append(field.message, message_len);
    if (backtrace_len != 0)
        logger.pending.append(field.backtrace, backtrace_len);
    if (method_len != 0)
        logger.pending.append(field.method, method_len);
    if (steering_len != 0)
        logger.pending.append(field.steering, steering_len);
    if (body_len != 0)
        logger.pending.append(field.body, body_len);
}

void log_internal_error(Logger &logger, const ErrorLine &line)
{
    if (mrb_unlikely(log_queue_full(logger)))
        return;
    if (!logger.enabled)
        return;
    const void *peer = line.peer.data();
    const size_t peer_len = line.peer.size();
    const char *request_target = line.request_target.data();
    const size_t request_target_len = line.request_target.size();
    const uint16_t status_code = line.status_code;
    const char *why = line.why.data();
    const size_t why_len = line.why.size();
    ErrFacts f;
    f.peer = peer;
    f.peer_len = peer_len;
    f.request_target = request_target;
    f.request_target_len = request_target_len;
    f.exception_class = "Webmachine::Error";
    f.exception_class_len = 17;
    f.message = why;
    f.message_len = why_len;
    f.status_code = status_code;
    log_error(logger, f);
}

void say_server_error(Logger *logger, std::string_view why)
{
    if (logger != nullptr && logger->enabled) {
        log_internal_error(*logger, {{}, {}, why, 0});
        return;
    }
    std::fprintf(stderr, "webmachine: %.*s\n", static_cast<int>(why.size()), why.data());
}

void log_raise(Logger &logger, mrb_state *mrb, uint16_t status)
{
    if (!logger.enabled)
        return;
    ErrFacts f;
    std::string backtrace;
    f.status_code = status;
    exception_facts(mrb, {f, backtrace});
    if (f.exception_class == nullptr)
        return;
    log_error(logger, f);
}

void report_raise(Logger *logger, mrb_state *mrb, uint16_t status)
{
    if (mrb->exc == nullptr)
        return;
    if (logger != nullptr)
        log_raise(*logger, mrb, status);
    if (kDebugBuild)
        mrb_print_error(mrb);
    mrb->exc = nullptr;
}

} // namespace webmachine

namespace webmachine::http
{
size_t path_only(const char *bytes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (bytes[i] == '?')
            return i;
    }
    return count;
}

flow::Method parse_method(const char *method, size_t count)
{
    switch (count) {
        case 3:
            if (std::memcmp(method, "GET", 3) == 0)
                return flow::Method::kGet;
            if (std::memcmp(method, "PUT", 3) == 0)
                return flow::Method::kPut;
            break;
        case 4:
            if (std::memcmp(method, "HEAD", 4) == 0)
                return flow::Method::kHead;
            if (std::memcmp(method, "POST", 4) == 0)
                return flow::Method::kPost;
            break;
        case 6:
            if (std::memcmp(method, "DELETE", 6) == 0)
                return flow::Method::kDelete;
            break;
        case 7:
            if (std::memcmp(method, "OPTIONS", 7) == 0)
                return flow::Method::kOptions;
            break;
        default:
            break;
    }
    return flow::Method::kOther;
}

std::string with_charset(const std::string &type)
{
    if (type.size() < 5 || !tok_eq({type.data(), 5}, "text/"))
        return type;
    if (type.find(';') != std::string::npos)
        return type;
    return type + "; charset=utf-8";
}

bool compressible_media_type(const std::string &value)
{
    return compressible_media_type(value.data(), value.size());
}

void write_two_digits(char *out_value, int value)
{
    out_value[0] = static_cast<char>('0' + value / 10);
    out_value[1] = static_cast<char>('0' + value % 10);
}

void date_core(char out_value[kDateLen], const struct tm &broken_time)
{
    static const char kDay[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::memcpy(out_value, kDay[broken_time.tm_wday], 3);
    out_value[3] = ',';
    out_value[4] = ' ';
    write_two_digits(out_value + 5, broken_time.tm_mday);
    out_value[7] = ' ';
    std::memcpy(out_value + 8, kMon[broken_time.tm_mon], 3);
    out_value[11] = ' ';
    const int year = broken_time.tm_year + 1900;
    write_two_digits(out_value + 12, year / 100);
    write_two_digits(out_value + 14, year % 100);
    out_value[16] = ' ';
    write_two_digits(out_value + 17, broken_time.tm_hour);
    out_value[19] = ':';
    write_two_digits(out_value + 20, broken_time.tm_min);
    out_value[22] = ':';
    write_two_digits(out_value + 23, broken_time.tm_sec);
    out_value[25] = ' ';
    std::memcpy(out_value + 26, "GMT", 3);
}

size_t spell_content_length(char (&buf)[40], size_t length)
{
    std::memcpy(buf, "Content-Length: ", 16);
    size_t at = 16;
    char digits[20];
    size_t d = 0;
    size_t v = length;
    do {
        digits[d++] = static_cast<char>('0' + v % 10);
        v /= 10;
    } while (v != 0);
    while (d != 0)
        buf[at++] = digits[--d];
    buf[at++] = '\r';
    buf[at++] = '\n';
    buf[at++] = '\r';
    buf[at++] = '\n';
    return at;
}

int hex_digit(char character)
{
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

ClStatus parse_content_length(std::string_view value, size_t *out_value)
{
    const char *const sqe = value.data();
    const size_t count = value.size();
    if (count == 0)
        return ClStatus::kBad;
    size_t acc = 0;
    for (size_t j = 0; j < count; j++) {
        const char character = sqe[j];
        if (character < '0' || character > '9')
            return ClStatus::kBad;
        size_t text = 0;
        if (__builtin_mul_overflow(acc, static_cast<size_t>(10), &text) ||
            __builtin_add_overflow(text, static_cast<size_t>(character - '0'), &acc)) {
            return ClStatus::kOverflow;
        }
    }
    *out_value = acc;
    return ClStatus::kOk;
}

void rebase(ReqValues &value, ptrdiff_t delta)
{
    for (const char *ReqValues::*m : kReqValueSpans) {
        if (value.*m != nullptr)
            value.*m += delta;
    }
}

void spell_steering(const ReqValues *value, std::string &out_value)
{
    out_value.clear();
    if (value == nullptr)
        return;
    const char *bytes = nullptr;
    size_t n = 0;
    const auto put = [&out_value](const char *name, const char *field_value, size_t length) {
        if (field_value == nullptr || length == 0)
            return;
        out_value.append(name);
        out_value.append(": ", 2);
        out_value.append(field_value, length);
        out_value.push_back('\n');
    };
    put("accept", value->accept, value->accept_len);
    put("accept-encoding", value->accept_encoding, value->accept_encoding_len);
    put("content-type", value->content_type, value->content_type_len);
    put("host", value->host, value->host_len);
    put("range", value->range, value->range_len);
    put("if-range", value->if_range, value->if_range_len);
    put("if-match", value->if_match, value->if_match_len);
    put("if-none-match", value->if_none_match, value->if_none_match_len);
    // The scheme is the first token; a line with no space is a scheme on
    // its own, which is all that goes down either way.
    if (value->authorization != nullptr && value->authorization_len != 0) {
        bytes = value->authorization;
        n = 0;
        while (n < value->authorization_len && bytes[n] != ' ' && bytes[n] != '\t')
            n++;
        put("authorization", bytes, n);
    }
    if (value->cookie != nullptr && value->cookie_len != 0)
        put("cookie", "sent", 4);
}

bool read_size(const char *value, size_t count, size_t &i, size_t *out_value)
{
    bool any = false;
    size_t val = 0;
    while (i < count && value[i] >= '0' && value[i] <= '9') {
        size_t text = 0;
        if (__builtin_mul_overflow(val, static_cast<size_t>(10), &text) ||
            __builtin_add_overflow(text, static_cast<size_t>(value[i] - '0'), &val)) {
            return false;
        }
        any = true;
        i++;
    }
    *out_value = val;
    return any;
}

RangeParse parse_range(RangeField field, ByteRange &out_value)
{
    const char *const value = field.value.data();
    const size_t count = field.value.size();
    const size_t complete = field.complete;
    size_t *const first = &out_value.first;
    size_t *const last = &out_value.last;
    if (count < 7 || !tok_eq({value, 6}, "bytes="))
        return RangeParse::kNone;
    size_t i = 6;
    while (i < count && (value[i] == ' ' || value[i] == '\t'))
        i++;
    size_t a = 0, b = 0;
    const bool have_a = read_size(value, count, i, &a);
    if (i >= count || value[i] != '-')
        return RangeParse::kNone;
    i++;
    const bool have_b = read_size(value, count, i, &b);
    while (i < count && (value[i] == ' ' || value[i] == '\t'))
        i++;
    if (i != count)
        return RangeParse::kNone;
    if (!have_a && !have_b)
        return RangeParse::kNone;
    if (complete == 0)
        return RangeParse::kUnsat;
    if (!have_a) {
        if (b == 0)
            return RangeParse::kUnsat;
        *first = b >= complete ? 0 : complete - b;
        *last = complete - 1;
        return RangeParse::kOne;
    }
    if (have_b && b < a)
        return RangeParse::kNone;
    if (a >= complete)
        return RangeParse::kUnsat;
    *first = a;
    *last = have_b ? (b < complete - 1 ? b : complete - 1) : complete - 1;
    return RangeParse::kOne;
}

bool if_range_matches(std::string_view value, std::string_view poll_tag)
{
    const char *const bytes = value.data();
    const size_t count = value.size();
    const size_t taglen = poll_tag.size();
    size_t i = 0;
    while (i < count && (bytes[i] == ' ' || bytes[i] == '\t'))
        i++;
    size_t e = count;
    while (e > i && (bytes[e - 1] == ' ' || bytes[e - 1] == '\t'))
        e--;
    return e - i == taglen && std::memcmp(bytes + i, poll_tag.data(), taglen) == 0;
}

bool gzip_acceptable(const char *value, size_t length)
{
    bool gz_seen = false, gz_ok = false, star_seen = false, star_ok = false;
    size_t i = 0;
    while (i < length) {
        while (i < length && (value[i] == ' ' || value[i] == '\t' || value[i] == ','))
            i++;
        const size_t timestamp = i;
        while (i < length && value[i] != ',' && value[i] != ';' && value[i] != ' ' &&
               value[i] != '\t')
            i++;
        const size_t tls = i - timestamp;
        bool q_nonzero = true;
        while (i < length && value[i] != ',') {
            if (value[i] != ';') {
                i++;
                continue;
            }
            i++;
            while (i < length && (value[i] == ' ' || value[i] == '\t'))
                i++;
            if (i < length && (value[i] == 'q' || value[i] == 'Q')) {
                size_t j = i + 1;
                while (j < length && (value[j] == ' ' || value[j] == '\t'))
                    j++;
                if (j < length && value[j] == '=') {
                    j++;
                    q_nonzero = false;
                    while (j < length && value[j] != ',' && value[j] != ';') {
                        if (value[j] >= '1' && value[j] <= '9')
                            q_nonzero = true;
                        j++;
                    }
                    i = j;
                }
            }
        }
        if (tls != 0) {
            if (tok_eq({value + timestamp, tls}, "gzip") ||
                tok_eq({value + timestamp, tls}, "x-gzip")) {
                gz_seen = true;
                gz_ok = q_nonzero;
            } else if (tls == 1 && value[timestamp] == '*') {
                star_seen = true;
                star_ok = q_nonzero;
            }
        }
    }
    if (gz_seen)
        return gz_ok;
    if (star_seen)
        return star_ok;
    return false;
}

bool etag_list_match(EtagMatch method)
{
    const char *const value = method.list.data();
    const size_t count = method.list.size();
    const char *const poll_tag = method.tag.data();
    const size_t taglen = method.tag.size();
    const bool weak = method.weak;
    size_t i = 0;
    while (i < count) {
        while (i < count && (value[i] == ' ' || value[i] == '\t' || value[i] == ','))
            i++;
        if (i >= count)
            break;
        bool member_weak = false;
        if (i + 1 < count && value[i] == 'W' && value[i + 1] == '/') {
            member_weak = true;
            i += 2;
        }
        if (i >= count || value[i] != '"') {
            while (i < count && value[i] != ',')
                i++;
            continue;
        }
        const size_t start = i;
        i++;
        while (i < count && value[i] != '"')
            i++;
        if (i >= count)
            break;
        i++;
        const size_t mlen = i - start;
        if ((weak || !member_weak) && mlen == taglen &&
            std::memcmp(value + start, poll_tag, taglen) == 0) {
            return true;
        }
    }
    return false;
}

int read_fixed_digits(const char *bytes, size_t index, size_t k)
{
    int v = 0;
    for (size_t i = 0; i < k; i++) {
        if (bytes[index + i] < '0' || bytes[index + i] > '9')
            return -1;
        v = v * 10 + (bytes[index + i] - '0');
    }
    return v;
}

int read_month_name(const char *bytes, size_t index)
{
    static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int m = 0; m < 12; m++) {
        if (std::memcmp(bytes + index, kMon[m], 3) == 0)
            return m + 1;
    }
    return -1;
}

int64_t epoch_from_civil(Civil conn)
{
    int y = conn.y;
    const int m = conn.m, d = conn.d, hh = conn.hh, mm = conn.mm, ss = conn.ss;
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const int yoe = y - era * 400;
    const int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const int64_t days = int64_t{era} * 146097 + doe - 719468;
    return days * 86400 + hh * 3600 + mm * 60 + ss;
}

bool parse_http_date(const char *bytes, size_t count, int64_t *out_value)
{
    int y, mo, d, hh, mm, ss;
    if (count == 29 && bytes[3] == ',' && bytes[4] == ' ') { // IMF-fixdate
        d = read_fixed_digits(bytes, 5, 2);
        mo = read_month_name(bytes, 8);
        y = read_fixed_digits(bytes, 12, 4);
        hh = read_fixed_digits(bytes, 17, 2);
        mm = read_fixed_digits(bytes, 20, 2);
        ss = read_fixed_digits(bytes, 23, 2);
        if (std::memcmp(bytes + 25, " GMT", 4) != 0)
            return false;
    } else if (count >= 28 && count <= 33 && std::memcmp(bytes + count - 4, " GMT", 4) == 0 &&
               static_cast<const char *>(std::memchr(bytes, ',', count)) != nullptr) { // RFC 850
        const char *conn = static_cast<const char *>(std::memchr(bytes, ',', count));
        const size_t index = static_cast<size_t>(conn - bytes) + 2;
        if (index + 18 + 4 != count || index + 18 > count)
            return false;
        d = read_fixed_digits(bytes, index, 2);
        if (bytes[index + 2] != '-' || bytes[index + 6] != '-')
            return false;
        mo = read_month_name(bytes, index + 3);
        y = read_fixed_digits(bytes, index + 7, 2);
        if (y >= 0)
            y += y < 70 ? 2000 : 1900; // 5.6.7's two-digit rule
        hh = read_fixed_digits(bytes, index + 10, 2);
        mm = read_fixed_digits(bytes, index + 13, 2);
        ss = read_fixed_digits(bytes, index + 16, 2);
    } else if (count == 24 && bytes[3] == ' ' && bytes[7] == ' ') { // asctime
        mo = read_month_name(bytes, 4);
        d = bytes[8] == ' ' ? read_fixed_digits(bytes, 9, 1) : read_fixed_digits(bytes, 8, 2);
        hh = read_fixed_digits(bytes, 11, 2);
        mm = read_fixed_digits(bytes, 14, 2);
        ss = read_fixed_digits(bytes, 17, 2);
        y = read_fixed_digits(bytes, 20, 4);
    } else {
        return false;
    }
    if (y < 0 || mo < 0 || d <= 0 || d > 31 || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 ||
        ss > 60) {
        return false;
    }
    *out_value = epoch_from_civil({y, mo, d, hh, mm, ss});
    return true;
}

bool accept_is_exact(std::string_view accept, std::string_view type)
{
    const char *const answer = accept.data();
    const size_t count = accept.size();
    size_t i = 0;
    while (i < count && (answer[i] == ' ' || answer[i] == '\t'))
        i++;
    if (count - i < type.size())
        return false;
    if (std::memcmp(answer + i, type.data(), type.size()) != 0)
        return false;
    i += type.size();
    while (i < count && (answer[i] == ' ' || answer[i] == '\t'))
        i++;
    return i == count || answer[i] == ',';
}

int choose_media_type(Conneg conn)
{
    const std::string *const types = conn.provided.data();
    const size_t ntypes = conn.provided.size();
    const char *const arguments = conn.accept.data();
    const size_t alen = conn.accept.size();
    struct Range {
        const char *t;
        size_t tn;
        const char *sub;
        size_t sn;
        int q1000;
    };
    Range ranges[32];
    size_t number = 0;
    size_t i = 0;
    while (i < alen && number < 32) {
        while (i < alen && (arguments[i] == ' ' || arguments[i] == '\t' || arguments[i] == ','))
            i++;
        if (i >= alen)
            break;
        const size_t start = i;
        while (i < alen && arguments[i] != ',')
            i++;
        const size_t text_end = i;
        int request = 1000;
        size_t semi = start;
        while (semi < text_end && arguments[semi] != ';')
            semi++;
        size_t tend = semi;
        while (tend > start && (arguments[tend - 1] == ' ' || arguments[tend - 1] == '\t'))
            tend--;
        size_t picture = semi;
        while (picture < text_end) {
            picture++;
            while (picture < text_end && (arguments[picture] == ' ' || arguments[picture] == '\t'))
                picture++;
            if (picture + 2 <= text_end &&
                (arguments[picture] == 'q' || arguments[picture] == 'Q') &&
                arguments[picture + 1] == '=') {
                size_t value = picture + 2;
                int whole = 0, frac = 0, fdig = 0;
                if (value < text_end && (arguments[value] >= '0' && arguments[value] <= '9')) {
                    whole = arguments[value] - '0';
                    value++;
                }
                if (value < text_end && arguments[value] == '.') {
                    value++;
                    while (value < text_end &&
                           (arguments[value] >= '0' && arguments[value] <= '9') && fdig < 3) {
                        frac = frac * 10 + (arguments[value] - '0');
                        fdig++;
                        value++;
                    }
                }
                while (fdig < 3) {
                    frac *= 10;
                    fdig++;
                }
                request = whole * 1000 + frac;
                if (request > 1000)
                    request = 1000;
            }
            while (picture < text_end && arguments[picture] != ';')
                picture++;
        }
        const char *slash =
            static_cast<const char *>(std::memchr(arguments + start, '/', tend - start));
        if (slash != nullptr) {
            ranges[number].t = arguments + start;
            ranges[number].tn = static_cast<size_t>(slash - (arguments + start));
            ranges[number].sub = slash + 1;
            ranges[number].sn = tend - static_cast<size_t>(slash + 1 - arguments);
            ranges[number].q1000 = request;
            number++;
        }
    }
    int best = -1;
    int best_q = 0;
    int best_spec = -1;
    for (size_t t = 0; t < ntypes; t++) {
        const std::string &full = types[t];
        size_t name = full.find(';');
        if (name == std::string::npos)
            name = full.size();
        while (name > 0 && full[name - 1] == ' ')
            name--;
        const char *type = full.data();
        const size_t slot = full.find('/');
        if (slot == std::string::npos || slot >= name)
            continue;
        const size_t main_n = slot;
        const char *sub_p = type + slot + 1;
        const size_t sub_n = name - slot - 1;
        int request = -1;
        int spec = -1;
        for (size_t round = 0; round < number; round++) {
            const Range &range = ranges[round];
            int this_spec;
            if (range.tn == 1 && range.t[0] == '*') {
                this_spec = 0;
            } else if (!tok_eq({range.t, range.tn}, {type, main_n})) {
                continue;
            } else if (range.sn == 1 && range.sub[0] == '*') {
                this_spec = 1;
            } else if (tok_eq({range.sub, range.sn}, {sub_p, sub_n})) {
                this_spec = 2;
            } else {
                continue;
            }
            if (this_spec > spec) {
                spec = this_spec;
                request = range.q1000;
            }
        }
        if (spec < 0 || request == 0)
            continue;
        if (request > best_q || (request == best_q && spec > best_spec)) {
            best = static_cast<int>(t);
            best_q = request;
            best_spec = spec;
        }
    }
    return best;
}

void etag_spell(const char *raw, size_t count, std::string &out_value)
{
    out_value.clear();
    if ((count >= 2 && raw[0] == '"') || (count >= 3 && raw[0] == 'W' && raw[1] == '/')) {
        out_value.append(raw, count);
        return;
    }
    out_value.push_back('"');
    out_value.append(raw, count);
    out_value.push_back('"');
}

void uri_join(UriRef round, std::string &out_value)
{
    const char *const base = round.base.data();
    const size_t blen = round.base.size();
    const char *const path = round.ref.data();
    const size_t payload_length = round.ref.size();
    out_value.clear();
    if (payload_length >= 8 && std::memcmp(path, "http", 4) == 0) {
        const char *colon = static_cast<const char *>(std::memchr(path, ':', payload_length));
        if (colon != nullptr && static_cast<size_t>(colon - path) <= 5) {
            out_value.append(path, payload_length);
            return;
        }
    }
    if (payload_length > 0 && path[0] == '/') {
        size_t slashes = 0, i = 0;
        for (; i < blen; i++) {
            if (base[i] == '/') {
                slashes++;
                if (slashes == 3)
                    break;
            }
        }
        out_value.append(base, i);
        out_value.append(path, payload_length);
        return;
    }
    size_t cut = blen;
    while (cut > 0 && base[cut - 1] != '/')
        cut--;
    if (cut == 0)
        cut = blen;
    out_value.append(base, cut);
    if (!out_value.empty() && out_value.back() != '/')
        out_value.push_back('/');
    out_value.append(path, payload_length);
}

bool field_name_is_the_servers(const char *bytes, size_t count)
{
    static constexpr const char *kOurs[] = {"content-length",  "transfer-encoding", "connection",
                                            "keep-alive",      "upgrade",           "te",
                                            "proxy-connection"};
    for (const char *ours : kOurs) {
        size_t i = 0;
        for (; i < count && ours[i] != '\0'; i++) {
            const unsigned char conn = static_cast<unsigned char>(bytes[i]);
            const unsigned char lowercase =
                (conn >= 'A' && conn <= 'Z') ? static_cast<unsigned char>(conn + 32) : conn;
            if (lowercase != static_cast<unsigned char>(ours[i]))
                break;
        }
        if (i == count && ours[i] == '\0')
            return true;
    }
    return false;
}

bool field_name_ok(const char *bytes, size_t count)
{
    if (count == 0)
        return false;
    for (size_t i = 0; i < count; i++) {
        const unsigned char conn = static_cast<unsigned char>(bytes[i]);
        const bool tchar = (conn >= 'a' && conn <= 'z') || (conn >= 'A' && conn <= 'Z') ||
                           (conn >= '0' && conn <= '9') || conn == '!' || conn == '#' ||
                           conn == '$' || conn == '%' || conn == '&' || conn == '\'' ||
                           conn == '*' || conn == '+' || conn == '-' || conn == '.' ||
                           conn == '^' || conn == '_' || conn == '`' || conn == '|' || conn == '~';
        if (!tchar)
            return false;
    }
    return true;
}

bool field_value_ok(const char *bytes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (bytes[i] == '\r' || bytes[i] == '\n' || bytes[i] == '\0')
            return false;
    }
    return true;
}

} // namespace webmachine::http

namespace webmachine::gzip
{
bool compress(const std::string &incoming, std::string &out_value)
{
    if (incoming.size() >= std::numeric_limits<uint32_t>::max())
        return false;
    z_stream strm{};
    if (deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return false;
    }
    const unsigned long bound = deflateBound(&strm, static_cast<unsigned long>(incoming.size()));
    out_value.assign(reinterpret_cast<const char *>(kHeader), sizeof(kHeader));
    const size_t body_off = out_value.size();
    out_value.resize(body_off + bound);
    strm.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(incoming.data()));
    strm.avail_in = static_cast<uInt>(incoming.size());
    strm.next_out = reinterpret_cast<Bytef *>(&out_value[0]) + body_off;
    strm.avail_out = static_cast<uInt>(bound);
    const int status = deflate(&strm, Z_FINISH);
    const size_t produced = strm.total_out;
    deflateEnd(&strm);
    if (status != Z_STREAM_END)
        return false;
    out_value.resize(body_off + produced);

    const uint32_t crc = static_cast<uint32_t>(
        crc32_z(0, reinterpret_cast<const Bytef *>(incoming.data()), incoming.size()));
    const uint32_t isize = static_cast<uint32_t>(incoming.size());
    unsigned char trailer[8];
    trailer[0] = static_cast<unsigned char>(crc);
    trailer[1] = static_cast<unsigned char>(crc >> 8);
    trailer[2] = static_cast<unsigned char>(crc >> 16);
    trailer[3] = static_cast<unsigned char>(crc >> 24);
    trailer[4] = static_cast<unsigned char>(isize);
    trailer[5] = static_cast<unsigned char>(isize >> 8);
    trailer[6] = static_cast<unsigned char>(isize >> 16);
    trailer[7] = static_cast<unsigned char>(isize >> 24);
    out_value.append(reinterpret_cast<const char *>(trailer), sizeof(trailer));
    return true;
}

} // namespace webmachine::gzip
