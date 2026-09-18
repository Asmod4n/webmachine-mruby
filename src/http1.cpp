#include <climits>
#include "webmachine.hpp"

#include "ring.hpp"

#include <picohttpparser.h>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace webmachine
{
namespace
{
// RFC 9110 7.6.1: Connection is a token list. A substring match would accept "not-close".
bool connection_field_holds_token(const char *value, size_t length, const char *lit, size_t litn)
{
    size_t i = 0;
    while (i < length) {
        while (i < length && (value[i] == ' ' || value[i] == '\t' || value[i] == ','))
            i++;
        const size_t start = i;
        while (i < length && value[i] != ',' && value[i] != ' ' && value[i] != '\t')
            i++;
        if (http::tok_eq({value + start, i - start}, {lit, litn}))
            return true;
    }
    return false;
}

using http::kDateLen;
using http::kDatePlaceholder;

struct WireFacts {
    size_t content_length = 0;
    const char *ws_key = nullptr;
    size_t ws_key_len = 0;
    int ws_version = 0;
    uint16_t out_error = 0;
    bool have_cl = false;
    bool have_te = false;
    // RFC 9112 7: chunked applied twice is malformed, so this is a count and not a flag.
    bool te_unknown_coding = false;
    bool te_last_is_chunked = false;
    uint8_t te_chunked_count = 0;
    bool have_host = false;
    bool conn_close = false;
    bool conn_keep = false;
    bool up_ws = false;
    bool conn_upgrade = false;
    bool expect_continue = false;
    bool expect_other = false;
};

// RFC 9110 5.3: several field lines with one name read as one comma-joined list, so a line
// adds to the list.
// RFC 9112 has no identity coding, so identity counts as unknown here.
static void transfer_encoding_fold(WireFacts &window, const char *value, size_t value_length)
{
    size_t at = 0;
    while (at < value_length) {
        while (at < value_length && (value[at] == ' ' || value[at] == '\t' || value[at] == ','))
            at++;
        const size_t from = at;
        while (at < value_length && value[at] != ',')
            at++;
        size_t to = at;
        while (to > from && (value[to - 1] == ' ' || value[to - 1] == '\t'))
            to--;
        if (to == from)
            continue;
        if (http::tok_eq({value + from, to - from}, "chunked")) {
            if (window.te_chunked_count < 0xff)
                window.te_chunked_count++;
            window.te_last_is_chunked = true;
        } else {
            window.te_unknown_coding = true;
            window.te_last_is_chunked = false;
        }
    }
}

constexpr size_t kWireLengths[] = {4, 6, 7, 10, 14, 17, 21};
constexpr uint32_t kWireLengthMask =
    http::lengths_mask(kWireLengths, sizeof(kWireLengths) / sizeof(kWireLengths[0]));

struct WireSink {
    WireFacts &window;
    http::ReqValues &vals;
    size_t index;
};

void wire_header_read(WireSink into, http::Field field)
{
    WireFacts &window = into.window;
    http::ReqValues &vals = into.vals;
    const size_t index = into.index;
    const char *const length = field.name.data();
    const size_t name_length = field.name.size();
    const char *const value = field.value.data();
    const size_t value_length = field.value.size();
    if (window.out_error != 0 || !http::length_is_one_of(name_length, kWireLengthMask))
        return;
    switch (name_length) {
        case 14:
            if (http::tok_eq({length, name_length}, "content-length")) {
                if (mrb_unlikely(window.have_cl)) {
                    window.out_error = 400;
                    return;
                }
                window.have_cl = true;
                vals.named.note(http::NamedField::kContentLength, index);
                switch (http::parse_content_length({value, value_length}, &window.content_length)) {
                    case http::ClStatus::kOk:
                        break;
                    case http::ClStatus::kBad:
                        window.out_error = 400;
                        break;
                    case http::ClStatus::kOverflow:
                        window.out_error = 413;
                        break;
                }
            }
            break;
        case 17:
            if (http::tok_eq({length, name_length}, "transfer-encoding")) {
                window.have_te = true;
                transfer_encoding_fold(window, value, value_length);
            } else if (http::tok_eq({length, name_length}, "sec-websocket-key")) {
                window.ws_key = value;
                window.ws_key_len = value_length;
            }
            break;
        case 4:
            if (http::tok_eq({length, name_length}, "host")) {
                if (mrb_unlikely(window.have_host))
                    window.out_error = 400;
                window.have_host = true;
            }
            break;
        case 10:
            if (http::tok_eq({length, name_length}, "user-agent")) {
                vals.log_ua = value;
                vals.log_ua_len = value_length;
            } else if (http::tok_eq({length, name_length}, "connection")) {
                if (connection_field_holds_token(value, value_length, "close", 5))
                    window.conn_close = true;
                else if (connection_field_holds_token(value, value_length, "keep-alive", 10))
                    window.conn_keep = true;
                if (connection_field_holds_token(value, value_length, "upgrade", 7))
                    window.conn_upgrade = true;
            }
            break;
        case 7:
            if (http::tok_eq({length, name_length}, "referer")) {
                vals.log_ref = value;
                vals.log_ref_len = value_length;
                break;
            }
            if (http::tok_eq({length, name_length}, "upgrade")) {
                window.up_ws = http::tok_eq({value, value_length}, "websocket");
            }
            break;
        case 21:
            if (http::tok_eq({length, name_length}, "sec-websocket-version")) {
                window.ws_version = 0;
                for (size_t j = 0; j < value_length; j++) {
                    if (value[j] < '0' || value[j] > '9') {
                        window.ws_version = -1;
                        break;
                    }
                    window.ws_version = window.ws_version * 10 + (value[j] - '0');
                    if (window.ws_version > 999) {
                        window.ws_version = -1;
                        break;
                    }
                }
            }
            break;
        case 6:
            if (http::tok_eq({length, name_length}, "expect")) {
                if (http::tok_eq({value, value_length}, "100-continue"))
                    window.expect_continue = true;
                else
                    window.expect_other = true;
            }
            break;
        default:
            break;
    }
}

struct SpelledHead {
    uint16_t status;
    const char *date;
    std::string_view ctype;
    std::string_view rhdrs;
    int minor;
    bool persist;
    bool bodyless;
    size_t length;
};

void head_spell(std::string &sink, const SpelledHead &head)
{
    const uint16_t status = head.status;
    char line[4];
    line[0] = static_cast<char>('0' + status / 100);
    line[1] = static_cast<char>('0' + (status / 10) % 10);
    line[2] = static_cast<char>('0' + status % 10);
    line[3] = '\0';
    sink.append("HTTP/1.1 ").append(line).append(" ").append(http::reason(status));
    sink.append("\r\nDate: ").append(head.date, kDateLen).append("\r\n");
    if (!head.ctype.empty())
        sink.append("Content-Type: ").append(head.ctype).append("\r\n");
    sink.append(head.rhdrs);
    if (!head.persist)
        sink.append("Connection: close\r\n");
    else if (head.minor < 1)
        sink.append("Connection: keep-alive\r\n");
    if (head.bodyless) {
        sink.append("\r\n");
        return;
    }
    char content_length[40];
    sink.append(content_length, http::spell_content_length(content_length, head.length));
}
} // namespace

void Http1::build_one_variant(Resp &response, Prebuilt bytes)
{
    response.bytes.clear();
    char line[16];
    line[0] = static_cast<char>('0' + bytes.status / 100);
    line[1] = static_cast<char>('0' + (bytes.status / 10) % 10);
    line[2] = static_cast<char>('0' + bytes.status % 10);
    line[3] = '\0';
    response.bytes.append("HTTP/1.1 ").append(line).append(" ").append(http::reason(bytes.status));
    response.bytes.append("\r\nDate: ");
    response.date_off = response.bytes.size();
    response.bytes.append(bytes.date)
        .append("\r\n")
        .append(bytes.conn)
        .append(bytes.extra)
        .append(bytes.body);
}

void Http1::copy_without_tail(const Resp &src, Resp &dst, size_t cut)
{
    dst.bytes.assign(src.bytes, 0, src.bytes.size() - cut);
    dst.date_off = src.date_off;
}

void Http1::build_open_prefix(Resp &response, OpenPrefix bytes)
{
    response.bytes.clear();
    response.bytes.append(bytes.status_line).append("\r\nDate: ");
    response.date_off = response.bytes.size();
    response.bytes.append(kDatePlaceholder)
        .append("\r\n")
        .append(bytes.conn)
        .append(bytes.extra)
        .append(bytes.enc);
}

void Http1::build_variants(Variants &value, Prebuilt bytes)
{
    bytes.conn = "";
    build_one_variant(value.plain, bytes);
    bytes.conn = "Connection: keep-alive\r\n";
    build_one_variant(value.keep, bytes);
    bytes.conn = "Connection: close\r\n";
    build_one_variant(value.close, bytes);
}

void Http1::build_open_prefixes(Variants &value, OpenPrefix bytes)
{
    bytes.conn = "";
    build_open_prefix(value.plain, bytes);
    bytes.conn = "Connection: keep-alive\r\n";
    build_open_prefix(value.keep, bytes);
    bytes.conn = "Connection: close\r\n";
    build_open_prefix(value.close, bytes);
}

void Http1::build_status(uint16_t status, StatusText status_text)
{
    Variants value;
    build_variants(value, {status, status_text.extra, status_text.body, kDatePlaceholder});
    Variants variants;
    build_variants(variants, {status, status_text.extra, "", kDatePlaceholder});
    index_[status] = static_cast<uint16_t>(store_.size());
    store_.push_back(std::move(value));
    store_prefix_.push_back(std::move(variants));
}

void Http1::patch_date(Variants &value, const char *core)
{
    std::memcpy(value.plain.bytes.data() + value.plain.date_off, core, kDateLen);
    std::memcpy(value.keep.bytes.data() + value.keep.date_off, core, kDateLen);
    std::memcpy(value.close.bytes.data() + value.close.date_off, core, kDateLen);
}

void Http1::build_bundle(Bundle &block, const Resource *resource)
{
    block.res = resource;
    block.konst = resource->konst;
    block.dynamic_body = resource->dynamic_body;
    block.bound = resource->dynamic != 0 || resource->dynamic_body;
    block.accept_type = block.konst.content_type;
    block.konst.content_type = http::with_charset(block.konst.content_type);
    block.index = index_;
    std::string ok_extra;
    if (!block.konst.content_type.empty()) {
        ok_extra = "Content-Type: " + block.konst.content_type + "\r\n";
    }
    const std::string ok_tail = "Content-Length: " + std::to_string(block.konst.body.size()) +
                                "\r\n\r\n" + block.konst.body;
    Variants accepted;
    build_variants(accepted, {200, ok_extra.c_str(), ok_tail.c_str(), kDatePlaceholder});
    const std::string allow = "Allow: " + block.konst.allow + "\r\n";
    Variants m405;
    build_variants(m405, {405, allow.c_str(), "Content-Length: 0\r\n\r\n", kDatePlaceholder});

    if (!block.bound) {
        unsigned char frame_head[kH2FrameHeaderLen];
        h2_put_frame_header(frame_head, {static_cast<uint32_t>(block.konst.body.size()), kH2Data,
                                         kH2FlagEndStream, 0});
        block.h2_data200.assign(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
        block.h2_data200.append(block.konst.body);
    }

    const size_t blen = block.konst.body.size();
    copy_without_tail(accepted.plain, block.ok_head.plain, blen);
    copy_without_tail(accepted.keep, block.ok_head.keep, blen);
    copy_without_tail(accepted.close, block.ok_head.close, blen);
    // A lent body must not sit in bytes that patch_date rewrites, so the 200 is kept without
    // its tail.
    {
        const size_t cut = ok_tail.size();
        copy_without_tail(accepted.plain, block.ok_prefix.plain, cut);
        copy_without_tail(accepted.keep, block.ok_prefix.keep, cut);
        copy_without_tail(accepted.close, block.ok_prefix.close, cut);
    }
    block.index[200] = static_cast<uint16_t>(store_.size());
    {
        // store_prefix_ shares index_ with store_, so the two vectors grow together.
        Variants p200;
        build_variants(p200, {200, ok_extra.c_str(), "", kDatePlaceholder});
        store_prefix_.push_back(std::move(p200));
    }
    store_.push_back(std::move(accepted));
    {
        H2Block hb;
        h2_build_block(hb, {200, &block.konst.content_type});
        h2_store_.push_back(std::move(hb));
    }
    block.index[405] = static_cast<uint16_t>(store_.size());
    {
        Variants p405;
        build_variants(p405, {405, allow.c_str(), "", kDatePlaceholder});
        store_prefix_.push_back(std::move(p405));
    }
    store_.push_back(std::move(m405));
    {
        H2Block hb;
        h2_build_block(hb, {405, nullptr, &block.konst.allow});
        h2_store_.push_back(std::move(hb));
    }
    block.gzip_ok = block.dynamic_body && resource->gzip_offered &&
                    http::compressible_media_type(block.konst.content_type);
    if (block.gzip_ok) {
        static const char kOk[] = "HTTP/1.1 200 OK";
        static const char kVary[] = "Vary: Accept-Encoding\r\n";
        static const char kGzip[] = "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n";
        build_open_prefixes(block.ok_prefix_vary, {kOk, ok_extra, kVary});
        build_open_prefixes(block.ok_prefix_gzip, {kOk, ok_extra, kGzip});
    }
    if (block.bound) {
        static const char kErr[] = "HTTP/1.1 500 Internal Server Error";
        build_open_prefixes(block.err_prefix, {kErr, ok_extra, ""});
        h2_build_block(block.h2_err, {500, &block.konst.content_type});
    }
}

Http1::Http1(const RouteTable &table, const Resource *const *resources, size_t nroutes,
             Assets *assets)
    : assets_(assets)
{
    const AppInput one{&table, resources, nroutes};
    http1_build_all(&one, 1);
}

Http1::Http1(const AppInput *apps, size_t napps, Assets *assets) : assets_(assets)
{
    http1_build_all(apps, napps);
}

void Http1::status_line_is_stocked(bool have[600], uint16_t text)
{
    if (have[text])
        return;
    have[text] = true;
    if (text == 204 || text == 304)
        build_status(text, {"", "\r\n"});
    else
        build_status(text, {"", "Content-Length: 0\r\n\r\n"});
    H2Block block;
    h2_build_block(block, {text});
    h2_store_.push_back(std::move(block));
}

void Http1::http1_build_all(const AppInput *apps, size_t napps)
{
    store_.reserve(32);
    bool have[600] = {};
    for (const auto &f : flow::kFlow) {
        if (f.on_true.status != 0)
            status_line_is_stocked(have, f.on_true.status);
        if (f.on_false.status != 0)
            status_line_is_stocked(have, f.on_false.status);
    }
    status_line_is_stocked(have, 400);
    status_line_is_stocked(have, 411);
    status_line_is_stocked(have, 413);
    status_line_is_stocked(have, 431);
    status_line_is_stocked(have, 404);
    status_line_is_stocked(have, 417);
    // index_ defaults to slot 0, so an absent status would spell whatever lives there.
    status_line_is_stocked(have, 500);
    status_line_is_stocked(have, 304);

    size_t total = 0;
    for (size_t asset_ask = 0; asset_ask < napps; asset_ask++)
        total += apps[asset_ask].nroutes;
    bundles_.resize(total);
    apps_.resize(napps);
    size_t index = 0;
    size_t ws_at = 0;
    size_t sse_at = 0;
    for (size_t asset_ask = 0; asset_ask < napps; asset_ask++) {
        apps_[asset_ask].table = apps[asset_ask].table;
        apps_[asset_ask].base = static_cast<uint16_t>(index);
        apps_[asset_ask].count = static_cast<uint16_t>(apps[asset_ask].nroutes);
        for (size_t i = 0; i < apps[asset_ask].nroutes; i++) {
            build_bundle(bundles_[index + i], apps[asset_ask].resources[i]);
        }
        index += apps[asset_ask].nroutes;
        apps_[asset_ask].ws_table =
            apps[asset_ask].ws_nroutes != 0 ? apps[asset_ask].ws_table : nullptr;
        apps_[asset_ask].ws_base = static_cast<uint16_t>(ws_at);
        for (size_t i = 0; i < apps[asset_ask].ws_nroutes; i++) {
            ws_res_.push_back(apps[asset_ask].ws_resources[i]);
        }
        ws_at += apps[asset_ask].ws_nroutes;
        apps_[asset_ask].sse_table =
            apps[asset_ask].sse_nroutes != 0 ? apps[asset_ask].sse_table : nullptr;
        apps_[asset_ask].sse_base = static_cast<uint16_t>(sse_at);
        apps_[asset_ask].tls = apps[asset_ask].tls;
        apps_[asset_ask].max_body = apps[asset_ask].max_body;
        for (size_t i = 0; i < apps[asset_ask].sse_nroutes; i++) {
            sse_res_.push_back(apps[asset_ask].sse_resources[i]);
        }
        sse_at += apps[asset_ask].sse_nroutes;
    }

    if (assets_ != nullptr) {
        h2_build_asset_shared();
        for (AssetEntry &e : assets_->entries())
            h2_build_asset_blocks(e);
    }

    sec_ = 0;
    clock_tick();
}

void Http1::swap_assets(Assets *assets)
{
    assets_ = assets;
    if (assets_ == nullptr)
        return;

    h2_build_asset_shared();
    for (AssetEntry &e : assets_->entries())
        h2_build_asset_blocks(e);
}

void Http1::clock_tick()
{
    const time_t now = ::time(nullptr);
    if (now == sec_)
        return;
    sec_ = now;
    struct tm tm;
    gmtime_r(&now, &tm);
    http::date_core(date_, tm);
    alog_.unix_seconds = static_cast<int64_t>(now);
    elog_.unix_seconds = static_cast<int64_t>(now);
    const char *core = date_;

    for (Variants &v : store_)
        patch_date(v, core);
    for (Variants &v : store_prefix_)
        patch_date(v, core);
    for (Bundle &b : bundles_) {
        patch_date(b.ok_head, core);
        patch_date(b.ok_prefix, core);
        if (b.gzip_ok) {
            patch_date(b.ok_prefix_vary, core);
            patch_date(b.ok_prefix_gzip, core);
        }
        if (b.bound)
            patch_date(b.err_prefix, core);
    }
}

void Http1::answer_assemble(std::string &sink, const Assembled &asset_ask)
{
    sink.append(asset_ask.prefix.bytes);
    sink.append(asset_ask.extra);
    char content_length[40];
    sink.append(content_length, http::spell_content_length(content_length, asset_ask.body.size()));
    if (!asset_ask.head_only)
        sink.append(asset_ask.body);
}

void Http1::assemble_dynamic(const DynamicBody &dynamic_body, std::string &sink)
{
    bool use_gzip = false;
    if (dynamic_body.may_gzip) {
        char content_length[40];
        const size_t cl_len = http::spell_content_length(content_length, dynamic_body.body.size());
        // The floor weighs the whole message, field lines included.
        if (dynamic_body.prefix_id.bytes.size() + dynamic_body.extra.size() + cl_len +
                dynamic_body.body.size() >=
            kCompressFloor) {
            use_gzip = gzip::compress(dynamic_body.body, gz_body_);
        }
    }
    if (use_gzip)
        answer_assemble(sink,
                        {dynamic_body.prefix_gz, gz_body_, dynamic_body.head_only,
                         dynamic_body.extra});
    else
        answer_assemble(sink, {dynamic_body.prefix_id, dynamic_body.body, dynamic_body.head_only,
                               dynamic_body.extra});
}

void Http1::open_error_assets(mrb_state *mrb, Assets *error_assets)
{
    error_assets_ = error_assets;
    err_pages_.open(mrb, error_assets, &elog_);
}

// RFC 9110 9.3.2: a HEAD answer carries the Content-Length a GET would send, and no body.
void Http1::spell_error(const ErrorAnswer &entry, std::string &sink)
{
    std::string body;
    size_t dlen = 0;
    const char *data =
        err_pages_.body_of_page({entry.status, entry.media, entry.fields}, body, &dlen);
    if (data == nullptr) {
        sink.append(entry.bodyless.bytes);
        return;
    }
    sink.append(entry.prefix.bytes);
    sink.append("Content-Type: ").append(err_pages_.media_type_of_slot(entry.media)).append("\r\n");
    char content_length[40];
    sink.append(content_length, http::spell_content_length(content_length, dlen));
    if (!entry.head_only)
        sink.append(data, dlen);
}

// RFC 3986 2.1: a target spells a byte a name cannot carry as a percent triplet.
// A malformed escape is refused and not kept. Kept, one file would have two spellings.
// A decoded NUL truncates a C string. A decoded '/' names no file. Both are refused.
enum class TargetName { kAsIs, kDecoded, kRefused };

TargetName target_decode(const char *path, size_t length, std::string &out_name)
{
    if (std::memchr(path, '%', length) == nullptr)
        return TargetName::kAsIs;

    out_name.clear();
    out_name.reserve(length);
    for (size_t i = 0; i < length; i++) {
        if (path[i] != '%') {
            out_name.push_back(path[i]);
            continue;
        }
        if (length - i < 3)
            return TargetName::kRefused;
        const int hi = http::hex_digit(path[i + 1]);
        const int lo = http::hex_digit(path[i + 2]);
        if (hi < 0 || lo < 0)
            return TargetName::kRefused;
        const char byte = static_cast<char>(hi * 16 + lo);
        if (byte == '\0' || byte == '/')
            return TargetName::kRefused;
        out_name.push_back(byte);
        i += 2;
    }
    return TargetName::kDecoded;
}

Http1::Took Http1::answer_from_assets(Round &round, std::string &sink, Plan *plan)
{
    Assets *tier = assets_;
    const char *apath = round.path;
    size_t alen = round.path_len;
    char abuf[PATH_MAX];
    if (error_assets_ != nullptr && round.path_len > kErrorAssetsPrefixLen &&
        std::memcmp(round.path, kErrorAssetsPrefix, kErrorAssetsPrefixLen) == 0) {
        const size_t rest = round.path_len - kErrorAssetsPrefixLen;
        if (rest + 1 < sizeof(abuf)) {
            abuf[0] = '/';
            std::memcpy(abuf + 1, round.path + kErrorAssetsPrefixLen, rest);
            tier = error_assets_;
            apath = abuf;
            alen = rest + 1;
        }
    }
    if (tier == nullptr)
        return Took::kNo;
    std::string decoded_name;
    switch (target_decode(apath, alen, decoded_name)) {
        case TargetName::kAsIs:
            break;
        case TargetName::kDecoded:
            apath = decoded_name.data();
            alen = decoded_name.size();
            break;
        case TargetName::kRefused:
            return Took::kNo;
    }
    AssetEntry *asset_entry = tier->find(apath, alen);
    if (asset_entry == nullptr)
        return Took::kNo;
    const uint16_t asset_status = tier->entry_verdict(*asset_entry, {round.facts, round.vals});
    const AssetStep step =
        asset_step(*asset_entry, {asset_status, round.head_only, round.facts.method, round.vals});
    const Assets::ConnectionOption connection_option =
        round.minor >= 1 ? (round.persist ? Assets::kNoConnectionField : Assets::kConnClose)
                         : (round.persist ? Assets::kKeepAlive : Assets::kConnClose);
    std::string epage;
    size_t eblen = 0;
    const char *ebody = nullptr;
    const char *ectype = nullptr;
    if (step.status_code >= 400 && step.head != AssetStep::HeadKind::kRefusal) {
        const int error_message = err_pages_.media_pick_for_status(
            step.status_code, round.vals.accept, round.vals.accept_len);
        const ErrorPages::Fields none;
        ebody = err_pages_.body_of_page({step.status_code, error_message, none}, epage, &eblen);
        if (ebody != nullptr)
            ectype = err_pages_.media_type_of_slot(error_message);
        else
            eblen = 0;
    }
    Assets::HeadAsk head{*asset_entry};
    head.status_code = step.status_code;
    head.conn = connection_option;
    head.date = date_;
    head.unix_seconds = sec_;
    head.first_byte_pos = step.first_byte_pos;
    head.last_byte_pos = step.first_byte_pos + step.content_length - 1;
    head.body_type = ectype;
    head.body_len = eblen;
    switch (step.head) {
        case AssetStep::HeadKind::kRefusal: {
            // 412 and 501 carry no field of this tier's own.
            const Variants &prefix_variants = prefixes(step.status_code);
            const Variants &status_variants = variants(step.status_code);
            const bool plain = round.minor >= 1;
            const ErrorPages::Fields none;
            const Resp &prefix =
                plain ? (round.persist ? prefix_variants.plain : prefix_variants.close)
                      : (round.persist ? prefix_variants.keep : prefix_variants.close);
            const Resp &bodyless =
                plain ? (round.persist ? status_variants.plain : status_variants.close)
                      : (round.persist ? status_variants.keep : status_variants.close);
            spell_error({prefix, bodyless, step.status_code,
                         err_pages_.media_pick_for_status(step.status_code, round.vals.accept,
                                                          round.vals.accept_len),
                         none, round.head_only},
                        sink);
            break;
        }
        case AssetStep::HeadKind::kUnsatisfiable:
            tier->answer_416_head(head, sink);
            break;
        case AssetStep::HeadKind::kRange:
            tier->answer_206_head(head, sink);
            break;
        case AssetStep::HeadKind::kNormal:
            tier->head_answer(head, sink);
            break;
    }
    const bool sent_page = ebody != nullptr && !round.head_only;
    if (sent_page)
        sink.append(ebody, eblen);
    bool started_xfer = false;
    if (step.sends_content) {
        round.st.asset = asset_entry;
        round.st.become(ConnMode::kAsset);
        round.st.asset_off = step.first_byte_pos;
        round.st.asset_end = step.first_byte_pos + step.content_length;
        started_xfer = true;
    }
    if (alog_.enabled) {
        log_access(alog_, {{static_cast<const char *>(round.st.peer), round.st.peer_len},
                           {round.method, round.method_len},
                           {round.path, round.path_len},
                           {round.vals.log_ref, round.vals.log_ref_len},
                           {round.vals.log_ua, round.vals.log_ua_len},
                           step.sends_content ? step.content_length : (sent_page ? eblen : 0),
                           step.status_code,
                           round.lflags});
    }
    // The caller learns round.off only once the round is taken, so the head is consumed here.
    round.off += round.head_len;
    if (round.content_length != 0) {
        const size_t avail = round.viewlen - round.off;
        const size_t skip = std::min(round.content_length, avail);
        round.off += skip;
        round.st.content_skip = round.content_length - skip;
    }
    if (!round.persist) {
        round.st.carry.clear();
        round.st.content_skip = 0;
        return Took::kClose;
    }
    if (started_xfer) {
        const size_t rest = round.viewlen - round.off;
        if (round.in_place)
            round.st.carry.assign(round.view + round.off, rest);
        else
            round.st.carry.erase(0, round.off);
        if (plan != nullptr) {
            const size_t room = plan->byte_cap == 0 ? round.st.asset_end - round.st.asset_off
                                : plan->byte_cap > sink.size() ? plan->byte_cap - sink.size()
                                                               : 0;
            size_t take = round.st.asset_end - round.st.asset_off;
            if (take > room)
                take = room;
            if (take > 0) {
                sink_claim(round.st, sink, *plan);
                struct iovec iov[3];
                const unsigned k =
                    Assets::entry_wire_iov(*round.st.asset, {round.st.asset_off, take}, iov);
                for (unsigned i = 0; i < k; i++) {
                    plan->iov[plan->iovlen++] =
                        Plan::Seg{static_cast<const char *>(iov[i].iov_base), 0, iov[i].iov_len};
                }
                plan->byte_total += take;
                round.st.asset_off += take;
                if (round.st.asset_off == round.st.asset_end) {
                    round.st.asset = nullptr;
                    round.st.become(ConnMode::kHead);
                    round.st.asset_off = 0;
                    round.st.asset_end = 0;
                }
            }
        }
        return Took::kOwed;
    }
    return Took::kNextRequest;
}

bool Http1::answer_from_file(Round &round, uint16_t status, const std::string &rhdrs)
{
    WantedFile wanted;
    if (!resource_file_wanted(*round.b->res, wanted) || status != 200)
        return false;

    Conn &conn = round.st;
    // Nothing is lent here. zc_release() still runs, for its h2-backlog drain.
    conn.zc_release();
    if (conn.file == nullptr)
        conn.file = new Conn::FileXfer();
    conn.file->pathname.assign(wanted.name);
    conn.file->field_lines = rhdrs;
    if (http::target_names_a_directory({round.path, round.path_len}) &&
        !http::freshness_is_stated(conn.file->field_lines)) {
        conn.file->field_lines.append(http::kNoCacheLine);
    }
    conn.file->content_type = !round.b->res->run.content_type.empty()
                                  ? http::with_charset(round.b->res->run.content_type)
                                  : round.b->konst.content_type;
    conn.file->minor = round.minor;
    conn.file->persist = round.persist;
    conn.file->head_only = round.head_only;
    conn.file->if_modified_since_valid =
        round.facts.has_if_modified_since && round.facts.if_modified_since_valid;
    conn.file->if_modified_since = round.vals.if_modified_since_epoch;
    conn.file->log_flags = round.lflags;
    conn.file->method_token.assign(round.method, round.method_len);
    conn.file->request_target.assign(round.path, round.path_len);
    conn.file->referer.assign(round.vals.log_ref != nullptr ? round.vals.log_ref : "",
                              round.vals.log_ref_len);
    conn.file->user_agent.assign(round.vals.log_ua != nullptr ? round.vals.log_ua : "",
                                 round.vals.log_ua_len);
    // A 404 can land long after this round, so its media type is picked while the request is
    // in hand.
    conn.file->err_media =
        err_pages_.media_pick_for_status(404, round.vals.accept, round.vals.accept_len);
    conn.file->stage = FileStage::kNamed;
    if (wanted.bad)
        file_reject(conn);
    file_named_tail(round);
    return true;
}

void Http1::file_named_tail(Round &round)
{
    Conn &conn = round.st;
    size_t offset = round.off;
    if (round.content_length != 0) {
        const size_t avail = round.viewlen - offset;
        const size_t skip = std::min(round.content_length, avail);
        offset += skip;
        conn.content_skip = round.content_length - skip;
    }
    if (!round.persist) {
        conn.carry.clear();
        conn.content_skip = 0;
    } else if (round.in_place) {
        conn.carry.assign(round.view + offset, round.viewlen - offset);
    } else {
        conn.carry.erase(0, offset);
    }
}

Http1::Took Http1::answer_from_docroot(Round &round)
{
    if (docroot_fd() < 0 || mime_ == nullptr)
        return Took::kNo;

    Conn &conn = round.st;
    const bool readable =
        round.facts.method == flow::Method::kGet || round.facts.method == flow::Method::kHead;

    size_t length = round.path_len;
    for (size_t i = 0; i < length; i++) {
        if (round.path[i] == '?') {
            length = i;
            break;
        }
    }
    std::string name;
    std::string decoded_name;
    bool undecodable = false;
    bool names_a_directory = false;
    switch (target_decode(round.path, length, decoded_name)) {
        case TargetName::kAsIs:
            if (length > 1)
                name.assign(round.path + 1, length - 1);
            break;
        case TargetName::kDecoded:
            if (decoded_name.size() > 1)
                name.assign(decoded_name, 1, std::string::npos);
            break;
        case TargetName::kRefused:
            undecodable = true;
            break;
    }
    if (name.empty() || name.back() == '/') {
        // With --listings the application answers a directory, because only it knows whether an
        // index document is there.
        if (listings_)
            return Took::kNo;
        name.append("index.html");
        names_a_directory = true;
    }

    // openat2 with RESOLVE_BENEATH would refuse these names too. Refusing here saves the ring
    // trip.
    bool bad = undecodable || name.find('\0') != std::string::npos;
    for (size_t index = 0; !bad && index < name.size();) {
        const size_t text_end = name.find('/', index);
        const std::string_view seg(
            name.data() + index, (text_end == std::string::npos ? name.size() : text_end) - index);
        if (seg.empty() || seg == "." || seg == "..")
            bad = true;
        if (text_end == std::string::npos)
            break;
        index = text_end + 1;
    }

    if (conn.file == nullptr)
        conn.file = new Conn::FileXfer();
    conn.file->pathname.assign(name);
    conn.file->field_lines.clear();
    if (names_a_directory)
        conn.file->field_lines.append(http::kNoCacheLine);
    conn.file->content_type = http::with_charset(mime_->type_of(name));
    conn.file->minor = round.minor;
    conn.file->persist = round.persist;
    conn.file->head_only = round.head_only;
    conn.file->if_modified_since_valid =
        round.facts.has_if_modified_since && round.facts.if_modified_since_valid;
    conn.file->if_modified_since = round.vals.if_modified_since_epoch;
    conn.file->log_flags = round.lflags;
    conn.file->method_token.assign(round.method, round.method_len);
    conn.file->request_target.assign(round.path, round.path_len);
    conn.file->referer.assign(round.vals.log_ref != nullptr ? round.vals.log_ref : "",
                              round.vals.log_ref_len);
    conn.file->user_agent.assign(round.vals.log_ua != nullptr ? round.vals.log_ua : "",
                                 round.vals.log_ua_len);
    conn.file->err_media =
        err_pages_.media_pick_for_status(404, round.vals.accept, round.vals.accept_len);
    conn.file->stage = FileStage::kNamed;
    if (!readable)
        file_prebuilt(conn, round.facts.method == flow::Method::kOther ? 501 : 405);
    else if (bad)
        file_reject(conn);
    // answer_from_file gets a Round whose off already stands past the head. This one does not.
    round.off += round.head_len;
    file_named_tail(round);
    return Took::kOwed;
}

bool Http1::connection_fail(Conn &conn, uint16_t code, std::string &out_answer, uint8_t log)
{
    if (alog_.enabled) {
        log_access(
            alog_,
            {{static_cast<const char *>(conn.peer), conn.peer_len}, {}, "-", {}, {}, 0, code, log});
    }
    const ErrorPages::Fields field;
    spell_error({prefixes(code).close, variants(code).close, code,
                 err_pages_.media_pick_for_status(code, nullptr, 0), field, false},
                out_answer);
    conn.carry.clear();
    conn.content_skip = 0;
    conn.content_need = 0;
    return false;
}

// Every site that splices into the plan claims the sink's uncovered tail first, so what
// follows lands at the right offset.
void Http1::sink_claim(Conn &conn, const std::string &sink, Plan &plan)
{
    if (sink.size() > conn.zc_covered) {
        const size_t head = sink.size() - conn.zc_covered;
        plan.iov[plan.iovlen++] = Plan::Seg{nullptr, conn.zc_covered, head};
        plan.byte_total += head;
    }
    conn.zc_covered = sink.size();
}

// feed_parse returns down many paths, so the split plan is closed here, once.
bool Http1::connection_feed(Conn &conn, std::string_view data, Sink out_answer)
{
    std::string &sink = out_answer.bytes;
    Plan *const plan = out_answer.plan;
    const bool accepted = feed_parse(conn, data, out_answer);
    if (mrb_unlikely(conn.zc_split) && plan != nullptr)
        sink_claim(conn, sink, *plan);
    return accepted;
}

void Http1::body_lend(Conn &conn, std::string &sink, Lending lend)
{
    Plan &plan = lend.plan;
    sink_claim(conn, sink, plan);
    plan.iov[plan.iovlen++] = Plan::Seg{lend.body.data(), 0, lend.body.size()};
    plan.byte_total += lend.body.size();
    conn.zc_split = true;
}

void Http1::file_prebuilt(Conn &conn, uint16_t status_code)
{
    const Variants &status_variants = variants(status_code);
    const Resp &bodyless =
        conn.file->minor >= 1 ? (conn.file->persist ? status_variants.plain : status_variants.close)
                              : (conn.file->persist ? status_variants.keep : status_variants.close);
    conn.file->head.clear();
    if (status_code >= 400) {
        const Variants &prefix_variants = prefixes(status_code);
        const Resp &prefix =
            conn.file->minor >= 1
                ? (conn.file->persist ? prefix_variants.plain : prefix_variants.close)
                : (conn.file->persist ? prefix_variants.keep : prefix_variants.close);
        const ErrorPages::Fields field;
        spell_error(
            {prefix, bodyless, status_code, conn.file->err_media, field, conn.file->head_only},
            conn.file->head);
    } else {
        conn.file->head = bodyless.bytes;
    }
    conn.file->status_code = status_code;
    conn.file->buf_filled = 0;
    conn.file->stage = FileStage::kDeliver;
}

void Http1::file_spell(Conn &conn, FileHead head_of)
{
    const uint16_t status_code = head_of.status;
    const size_t content_length = head_of.content_length;
    const bool bodyless = head_of.bodyless;
    conn.file->head.clear();
    const SpelledHead head = {status_code,
                              date_,
                              bodyless ? std::string_view() : conn.file->content_type,
                              conn.file->field_lines,
                              conn.file->minor,
                              conn.file->persist,
                              bodyless,
                              content_length};
    head_spell(conn.file->head, head);
    conn.file->status_code = status_code;
    conn.file->buf_filled = bodyless || conn.file->head_only ? 0 : content_length;
    conn.file->stage = FileStage::kDeliver;
}

// The SQE points at pathname's bytes, so nothing clears it until the answer is spelled.
const char *Http1::file_take(Conn &conn)
{
    if (conn.file == nullptr || conn.file->stage != FileStage::kNamed)
        return nullptr;
    conn.file->stage = FileStage::kRing;
    return conn.file->pathname.c_str();
}

// One answer for every refusal, so an attacker cannot tell a caught escape from a miss.
void Http1::file_reject(Conn &conn)
{
    file_prebuilt(conn, 404);
}

bool Http1::file_redirect_to_directory(Conn &conn)
{
    const std::string &target = conn.file->request_target;
    // RFC 9112 3.2: a target holds no space and no control byte. The value goes into a
    // field line, so it is checked again here.
    for (const char byte : target) {
        const unsigned char value = static_cast<unsigned char>(byte);
        if (value < 0x21 || value > 0x7e)
            return false;
    }
    const size_t query = target.find('?');
    const std::string_view path(target.data(), query == std::string::npos ? target.size() : query);
    if (path.empty() || path.back() == '/')
        return false;
    conn.file->field_lines.append("Location: ").append(path).append("/");
    if (query != std::string::npos)
        conn.file->field_lines.append(target, query, std::string::npos);
    conn.file->field_lines.append("\r\n");
    // RFC 9112 6.3: a kept-alive client needs Content-Length: 0. RFC 9110 15.4.5 lets 304
    // omit it, and 301 is not 304.
    conn.file->content_type.clear();
    file_spell(conn, {301, 0, false});
    return true;
}

// A body whole on the wire is not yet whole in its file, and the run reads the file.
void Http1::spill_wrote(Conn &conn, ssize_t resource, const std::string &out_answer)
{
    BodySpill *sp = nullptr;
    if (conn.spill.in_flight) {
        sp = &conn.spill;
    } else if (conn.h2 != nullptr) {
        for (H2Stream &s : conn.h2->streams) {
            if (s.spill.in_flight) {
                sp = &s.spill;
                break;
            }
        }
    }
    if (sp == nullptr)
        return;
    sp->wrote(resource, out_answer);
    if (sp == &conn.spill && sp->ended && sp->drained() && conn.run_wants_body) {
        Conn::Round *const round =
            conn.park_at(conn.parked.co ? conn.parked.co.promise().park : -1);
        if (round != nullptr)
            round->answer_ready = true;
    }
    if (mrb_unlikely(sp->failed)) {
        if (sp == &conn.spill) {
            conn.body_to = Conn::Body::kNone;
            conn.content_need = 0;
            conn.run_wants_body = false;
        }
        return;
    }
}

void Http1::file_error(Conn &conn, const char *why)
{
    log_internal_error(elog_, {{static_cast<const char *>(conn.peer), conn.peer_len},
                               conn.file->request_target,
                               why,
                               500});
    // Once a window went out, the head named a Content-Length the body cannot reach.
    // RFC 9112 6.3: only a close says the representation is incomplete.
    if (conn.file->content_sent != 0) {
        conn.file->content_length = conn.file->content_sent;
        conn.file->buf_filled = 0;
        conn.file->persist = false;
        conn.file->stage = FileStage::kDeliver;
        return;
    }
    file_prebuilt(conn, 500);
}

bool Http1::file_stat(Conn &conn, const struct statx &file_stat, size_t *want)
{
    if (!S_ISREG(file_stat.stx_mode)) {
        // The listing hangs relative links under the trailing slash, so a directory without
        // it is redirected.
        if (listings_ && S_ISDIR(file_stat.stx_mode) && file_redirect_to_directory(conn)) {
            return false;
        }
        // Naming which kind of file this is would be the distinguishable answer this path avoids.
        file_reject(conn);
        return false;
    }
    const size_t length = static_cast<size_t>(file_stat.stx_size);

    const int64_t mtime = static_cast<int64_t>(file_stat.stx_mtime.tv_sec);
    char lm[http::kDateLen];
    {
        const time_t status_text = static_cast<time_t>(mtime);
        struct tm tm;
        gmtime_r(&status_text, &tm);
        http::date_core(lm, tm);
    }
    conn.file->field_lines.append("Last-Modified: ").append(lm, http::kDateLen).append("\r\n");

    // RFC 9110 13.1.3 / 15.4.5: no newer than what the client already holds.
    if (conn.file->if_modified_since_valid && mtime <= conn.file->if_modified_since) {
        file_spell(conn, {304, 0, true});
        return false;
    }
    if (conn.file->head_only || length == 0) {
        file_spell(conn, {200, length, false});
        return false;
    }
    file_spell(conn, {200, length, false});
    conn.file->stage = FileStage::kRing;
    conn.file->content_length = length;
    conn.file->content_sent = 0;
    // [tune] file_map_threshold: 0 is "never map", so it is not a plain >=.
    conn.file->map_wanted = map_min_ != 0 && length >= map_min_;
    *want = length < kResponseFileWindow ? length : kResponseFileWindow;
    return true;
}

// Called only with no read in flight.
char *Http1::file_buffer(Conn &conn, size_t length)
{
    if (conn.file->chunk.size() < length)
        conn.file->chunk.resize(length);
    return &conn.file->chunk[0];
}

void Http1::file_mapped(Conn &conn, const char *bytes, size_t length)
{
    // A mapping still installed here was lent to no round, so nothing else releases it.
    conn.map_release();
    conn.file->map_addr = bytes;
    conn.file->map_length = length;
    conn.file->buf_filled = length;
    conn.file->content_length = length;
    conn.file->content_sent = 0;
    conn.file->stage = FileStage::kDeliver;
}

void Http1::file_apply(Conn &conn, const FileStep &step)
{
    if (conn.file == nullptr)
        return;
    conn.file->content_sent = step.sent_after;
    conn.file->stage = step.next;
    if (step.head)
        conn.file->head.clear();
    if (step.log)
        file_log(conn); // before file_clear takes the strings
    if (step.release_map)
        conn.map_release();
    if (step.clear)
        conn.file_clear();
}

void Http1::file_log(Conn &conn)
{
    if (!alog_.enabled || conn.file == nullptr)
        return;
    const Conn::FileXfer &one = *conn.file;
    log_access(alog_, {{static_cast<const char *>(conn.peer), conn.peer_len},
                       one.method_token,
                       one.request_target,
                       one.referer,
                       one.user_agent,
                       one.content_sent,
                       one.status_code,
                       one.log_flags});
}

// A transfer at kNone has already written its line. The stage is the guard against a
// second one.
void Http1::file_abandon(Conn &conn)
{
    if (conn.file == nullptr || conn.file->stage == FileStage::kNone)
        return;
    file_log(conn);
    conn.file->stage = FileStage::kNone;
}

void Http1::file_ready_now(Conn &conn, size_t length)
{
    conn.file->buf_filled = length;
    conn.file->stage = FileStage::kDeliver;
}

// phr_header is incomplete in webmachine.hpp, and unique_ptr<T[]> needs T complete where
// these are defined.
Http1::Held::Held() = default;
Http1::Held::~Held() = default;
Http1::Held::Held(Held &&) noexcept = default;
Http1::Held &Http1::Held::operator=(Held &&) noexcept = default;

void Http1::Held::hold(const char *head_at, size_t head_len, const ReqView &from,
                       const std::string *target)
{
    // A second stop already reads this copy. Copying it onto itself would free the fields
    // array it reads from.
    if (!head.empty() && head_at == head.data())
        return;
    const std::string_view was_head{head_at, head_len};
    head.assign(was_head);
    const std::string_view now_head{head};
    // A pointer in neither run is left where it is.
    std::string_view was_target;
    std::string_view now_target;
    if (target != nullptr && from.request_target != nullptr) {
        was_target = {from.request_target, from.request_target_len};
        now_target = *target;
    }
    const auto move = [&](const char *&bytes) {
        if (!http::follow_copy(was_head, now_head, bytes))
            http::follow_copy(was_target, now_target, bytes);
    };

    vals = *from.values;
    http::rebase(vals, was_head, now_head);

    nfields = from.field_count;
    if (nfields != 0) {
        fields = std::make_unique<struct phr_header[]>(nfields);
        const auto *src = static_cast<const struct phr_header *>(from.fields);
        for (size_t i = 0; i < nfields; i++) {
            fields[i] = src[i];
            // A field pointer in neither run stays where it is. An h2 host field's name is a
            // literal that lies in neither.
            move(fields[i].name);
            move(fields[i].value);
        }
    }
    vals.named = from.values->named;

    // Past nbind the array is uninitialised by contract.
    if (from.spans != nullptr) {
        spans = *from.spans;
        for (uint8_t i = 0; i < spans.nbind; i++) {
            move(spans.bind[i].p);
        }
        if (spans.has_splat)
            move(spans.splat.p);
    }

    rv = from;
    move(rv.request_target);
    move(rv.method_token);
    rv.values = &vals;
    rv.fields = fields.get();
    rv.spans = from.spans != nullptr ? &spans : nullptr;
    // The body lies in the same buffer as the head. A file body outlives every buffer, so it
    // needs no copy.
    if (from.content != nullptr && from.content_len != 0) {
        content.assign(from.content, from.content_len);
        rv.content = content.data();
    } else {
        rv.content = from.content;
    }
    rv.content_len = from.content_len;

    // kReqValueSpans is a list, and a list can be short by one member. This finds the
    // forgotten member on the first parked run in a debug build.
    if constexpr (kDebugBuild) {
        const uintptr_t low = reinterpret_cast<uintptr_t>(head_at);
        const uintptr_t high = low + head_len;
        const unsigned char *raw = reinterpret_cast<const unsigned char *>(&vals);
        for (size_t i = 0; i + sizeof(uintptr_t) <= sizeof(vals); i += sizeof(uintptr_t)) {
            uintptr_t window = 0;
            std::memcpy(&window, raw + i, sizeof(window));
            if (window >= low && window < high) {
                std::fprintf(stderr,
                             "webmachine: #80 hold() left a ReqValues word at offset %zu pointing "
                             "into the buffer it was supposed to leave - add the member to "
                             "kReqValueSpans\n",
                             i);
                std::abort();
            }
        }
    }
}

void Http1::bound_prepare(Round &round, const BoundAsk &request_ask, BoundPrep &prep)
{
    Conn &conn = round.st;
    const Bundle *const block = round.b;
    const char *const view = round.view;
    const size_t offset = round.off - round.head_len;
    const size_t head_len = round.head_len;
    const char *const method = round.method;
    const size_t method_len = round.method_len;
    const char *const path = round.path;
    const size_t path_len = round.path_len;
    const bool head_only = round.head_only;
    const flow::ReqFacts &facts = round.facts;
    const http::ReqValues &vals = round.vals;
    const struct phr_header *const headers =
        static_cast<const struct phr_header *>(request_ask.fields);
    const size_t num_headers = request_ask.nfields;
    const RouteSpans &spans = request_ask.spans;
    Plan *const plan = request_ask.plan;
    ReqView &result = prep.rv;
    result.request_target = path;
    result.request_target_len = path_len;
    result.path_len = http::path_only(path, path_len);
    result.method = facts.method;
    result.method_token = method;
    result.method_token_len = method_len;
    result.table = request_ask.table;
    result.route = request_ask.route;
    result.spans = &spans;
    result.fields = headers;
    result.field_count = num_headers;
    result.values = &vals;
    // RFC 9112 7.1: a chunked body declares no length, so the count is what arrived.
    const bool chunked = conn.body_to == Conn::Body::kChunkMem ||
                         conn.body_to == Conn::Body::kChunkFile || conn.body_count != 0;
    result.declared_len = chunked ? conn.body_count : round.content_length;
    if ((round.content_length != 0 || chunked) && block->res->takes_body) {
        // A file body is ready only once the last spill write landed. request.body.save links
        // that file.
        const bool on_wire = chunked ? conn.body_to == Conn::Body::kNone : conn.content_need == 0;
        result.content_ready = on_wire && (conn.spill.fd < 0 || conn.spill.drained());
        if (!result.content_ready) {
        } else if (conn.spill.fd >= 0) {
            result.content_fd = conn.spill.fd;
            result.content_len = conn.spill.written;
            conn.spill.bound = true;
        } else if (chunked) {
            result.content = conn.body_hold.empty() ? nullptr : conn.body_hold.data();
            result.content_len = conn.body_hold.size();
        } else {
            result.content = view + offset + head_len;
            result.content_len = round.content_length;
        }
    }
    prep.accept_gzip = !facts.has_accept_encoding ||
                       http::gzip_acceptable(vals.accept_encoding, vals.accept_encoding_len);
    // A lend needs a plan, one lend per connection, no HEAD and no gzip. Nothing downstream
    // may touch the bytes.
    const bool gz_now = prep.accept_gzip && block->gzip_ok && conn.packetized;
    prep.zc_min =
        (zc_min_ != 0 && plan != nullptr && !conn.zc_lent && !head_only && !gz_now) ? zc_min_ : 0;
}

Http1::Took Http1::bound_finish(Round &round, const BoundAsk &request_ask, BoundOut &out_answer)
{
    Conn &conn = round.st;
    const Bundle *const block = round.b;
    const bool head_only = round.head_only;
    const int minor = round.minor;
    const bool persist = round.persist;
    const http::ReqValues &vals = round.vals;
    Plan *const plan = request_ask.plan;
    std::string &sink = request_ask.sink;
    uint16_t status = out_answer.status;
    bool have_body = out_answer.have_body;
    bool answered = false;
    const char *lent = nullptr;
    size_t lent_len = 0;
    LentBody lent_body;
    if (mrb_unlikely(resource_body_lent(*block->res, lent_body))) {
        conn.zc_value = lent_body.value;
        lent = lent_body.bytes.data();
        lent_len = lent_body.bytes.size();
        conn.zc_mrb = block->res->mrb;
        conn.zc_lent = true;
    }
    // An error asset lives in a mapping that outlives every request, so nothing here is
    // rooted or released.
    if (mrb_unlikely(block->res->run.asset != nullptr)) {
        const AssetEntry &asset_entry = *block->res->run.asset;
        const size_t length = Assets::wire_len(asset_entry);
        if (plan != nullptr) {
            struct iovec iov[3];
            const unsigned k = Assets::entry_wire_iov(asset_entry, {0, length}, iov);
            // A deflated entry would be three segments, and the head spelled here carries no
            // Content-Encoding.
            lent = k == 1 ? static_cast<const char *>(iov[0].iov_base) : nullptr;
            lent_len = k == 1 ? iov[0].iov_len : 0;
        }
        if (lent == nullptr) {
            request_ask.body.clear();
            Assets::entry_copy_wire(asset_entry, {0, length}, request_ask.body);
        }
    }
    {
        if (mrb_unlikely(answer_from_file(round, status, request_ask.rhdrs))) {
            request_ask.body.clear();
            out_answer.status = status;
            out_answer.have_body = false;
            out_answer.answered = false;
            out_answer.lent = nullptr;
            out_answer.lent_len = 0;
            return Took::kOwed;
        }
    }
    if (mrb_unlikely((!block->res->run.content_type.empty() || !request_ask.rhdrs.empty()) &&
                     status != 500)) {
        const bool bodyless = status == 204 || status == 304;
        if (bodyless || !have_body) {
            request_ask.body.clear();
            conn.zc_release();
            lent = nullptr;
            lent_len = 0;
        }
        // A `def self.to_html` body is rendered at setup into the prebuilt 200, which is not
        // the head spelled here.
        const bool baked = !bodyless && !have_body && lent == nullptr && status == 200 &&
                           !block->dynamic_body && !block->konst.body.empty();
        if (status < 400 && http::target_names_a_directory({round.path, round.path_len}) &&
            !http::freshness_is_stated(request_ask.rhdrs)) {
            request_ask.rhdrs.append(http::kNoCacheLine);
        }
        std::string ctype;
        std::string epage;
        // RFC 9110 15: a 4xx or 5xx is owed its page. A run with a field of its own lands here
        // instead of at spell_error.
        if (status >= 400 && !bodyless && !have_body && lent == nullptr) {
            const int error_message =
                err_pages_.media_pick_for_status(status, vals.accept, vals.accept_len);
            size_t elen = 0;
            const ErrorPages::Fields none;
            const char *error_page =
                err_pages_.body_of_page({status, error_message, none}, epage, &elen);
            if (error_page != nullptr) {
                request_ask.body.assign(error_page, elen);
                have_body = true;
                ctype = err_pages_.media_type_of_slot(error_message);
            }
        }
        if (!bodyless && ctype.empty()) {
            if (!block->res->run.content_type.empty()) {
                ctype = http::with_charset(block->res->run.content_type);
            } else if (have_body || baked)
                ctype = block->konst.content_type;
        }
        const SpelledHead head = {
            status,
            date_,
            ctype,
            request_ask.rhdrs,
            minor,
            persist,
            bodyless,
            lent != nullptr ? lent_len
                            : (baked ? block->konst.body.size() : request_ask.body.size())};
        head_spell(sink, head);
        if (!bodyless && !head_only) {
            if (lent != nullptr)
                body_lend(conn, sink, {{lent, lent_len}, *plan});
            else
                sink.append(baked ? block->konst.body : request_ask.body);
        }
        have_body = false;
        answered = true;
    }

    out_answer.status = status;
    out_answer.have_body = have_body;
    out_answer.answered = answered;
    out_answer.lent = lent;
    out_answer.lent_len = lent_len;
    return Took::kNextRequest;
}

// At a stop the request pointers point into a provided buffer that on_recv hands back to
// the kernel. A coroutine frame is the copy that cannot be short by one member.
Http1::ComputeRound Http1::start_compute_round(Conn &conn, const BoundStart &text,
                                               std::string *sink, Plan *plan, size_t &offset)
{
    conn.parked = run_parkable(conn, {RunStart::Proto::kH1, text}, sink, plan);
    offset = text.off;
    // A run that waits for the body reads the octets from the hold, so they are not stepped
    // over.
    if (text.content_length != 0 && !conn.run_wants_body) {
        const size_t avail = text.viewlen - offset;
        const size_t skip = std::min(text.content_length, avail);
        offset += skip;
        conn.content_skip = text.content_length - skip;
    }
    if (!conn.parked.done()) {
        // RFC 9112 9.3.2: answers go out in request order, so what is behind a stopped run waits
        // in the carry.
        const size_t rest = text.viewlen - offset;
        if (text.in_place)
            conn.carry.assign(text.view + offset, rest);
        else
            conn.carry.erase(0, offset);
        return ComputeRound::kParked;
    }
    const bool alive = conn.parked.co.promise().persist;
    conn.parked.destroy();
    if (!alive) {
        conn.carry.clear();
        conn.content_skip = 0;
        return ComputeRound::kClosed;
    }
    return ComputeRound::kNext;
}

Http1::Run Http1::run_parkable(Conn &conn, RunStart start, std::string *sink, Plan *plan)
{
    const bool h1 = start.proto == RunStart::Proto::kH1;
    BoundStart text = start.h1;
    const Bundle *const block = h1 ? text.b : nullptr;

    // A parked run may share no scratch with the next request on this connection.
    std::string body;
    std::string rhdrs;
    Held held;
    bool have_body = false;
    // The h2 stream table is a vector that a new HEADERS frame may move, so the frame holds
    // the body.
    std::string h2_content;

    Run::promise_type &me = co_await Self{};
    me.persist = h1 ? text.persist : true;

    {
        BoundPrep prep;
        H2Produced hpack;
        bool stopped = false;
        // The dispatch's decode buffer is gone by the time a stopped run answers, so the head is
        // copied here.
        const bool h2_held = !h1 && start.h2.view != nullptr && start.h2.head_at != nullptr;
        // A parked stream's target lies beside its fields, not inside them, so hold takes both.
        if (h2_held) {
            held.hold(start.h2.head_at, start.h2.head_len, *start.h2.view, &start.h2.target);
        }
        H2Request hq = {start.h2.stream_id,
                        start.h2.facts,
                        h2_held ? &held.vals : nullptr,
                        h2_held ? &held.rv : nullptr,
                        start.h2.target,
                        start.h2.route,
                        start.h2.head_only};
        hq.bundle = start.h2.route == kNoRoute
                        ? nullptr
                        : &bundles_[apps_[conn.listener].base + start.h2.route];
        uint16_t status = 0;
        if (h1) {
            Round r{
                conn,          block,         text.view,    text.viewlen,    text.off,
                text.head_len, text.in_place, text.method,  text.method_len, text.path,
                text.path_len, text.minor,    text.persist, text.head_only,  text.content_length,
                text.lflags,   text.facts,    text.vals};
            const BoundAsk request_ask = {text.fields, text.nfields, text.spans,
                                          text.table,  text.route,   plan,
                                          *sink,       body,         rhdrs};
            bound_prepare(r, request_ask, prep);

            const RunAsk asked = {text.facts, &text.vals, &prep.rv, prep.zc_min, true};
            const RunAnswer answer = {&body, &have_body, &rhdrs};
            status = resource_run(*block->res, asked, answer);
        } else {
            hpack.body = &body;
            hpack.rhdrs = &rhdrs;
            h2_produce(conn, hq, true, hpack);
            status = hpack.status;
            have_body = hpack.have_body;
        }
        const Bundle *const rb = h1 ? block : hpack.b;
        const Resource *const ran = (rb != nullptr && rb->bound) ? rb->res : nullptr;

        // A completion carries a number and not a pointer, so the connection learns this round
        // through a park slot.
        Conn::Round mine_round;
        int park = -1;
        while (mrb_unlikely(ran != nullptr && run_stopped(*ran))) {
            const Resource &resource = *ran;
            if (h1) {
                held.hold(text.head_at, text.head_len, prep.rv, nullptr);
                text.head_at = held.head.data();
                prep.rv = held.rv;
                text.view = held.head.data();
                text.viewlen = held.head.size();
                text.off = held.head.size();
                text.method = held.rv.method_token;
                text.path = held.rv.request_target;
                text.fields = held.fields.get();
                text.nfields = held.nfields;
                text.spans = held.spans;
                text.vals = held.vals;
            }

            // The hand-over below reads res.run, so it runs before the move that takes it.
            if (park < 0) {
                park = conn.park_take(&mine_round);
                me.park = park;
            }
            // A run waiting for the body owes nothing to a worker. The last octet makes the round
            // ready.
            if (mrb_unlikely(resource.run.wants_body)) {
                mine_round.wants_body = true;
                mine_round.jobs_owed = 0;
            } else {
                compute_task_hand_over(conn, mine_round, park, resource);
                // A watcher nobody roots is collected while its descriptor is still in the ring, so
                // it reaches the connection's hash before res.run moves.
                if (resource.run.watch_count != 0 &&
                    !watch_hand_over(conn, mine_round, park, resource)) {
                    mine_round.answer_value.at(0) = mrb_nil_value();
                    mine_round.jobs_owed = 0;
                    mine_round.answer_ready = true;
                }
            }

            // res.run belongs to the route, and the next request on it would write over this. Each
            // watcher is told where the moved state lives.
            Resource::RunState mine = std::move(resource.run);
            resource.run = Resource::RunState{};
            watch_run_is(conn, mine_round, &mine);
            // If the frame dies while the run waits, the roots run_settle took go back here. On
            // resume res.run owns them again.
            struct ParkedRoots {
                const Resource *resource;
                Resource::RunState *state;
                Conn::Round *round;
                ~ParkedRoots()
                {
                    if (resource == nullptr)
                        return;
                    resource_abandon(*resource, *state);
                    for (mrb_value &a : round->answer_value) {
                        if (!mrb_nil_p(a))
                            mrb_gc_unregister(resource->mrb, a);
                        a = mrb_nil_value();
                    }
                }
            } parked_roots{&resource, &mine, &mine_round};

            Run::promise_type &promise = co_await Park{};
            parked_roots.resource = nullptr;
            stopped = true;

            // The sink and plan this run started with were locals of a parse that has returned.
            // RFC 9112 9.3: persist was decided by the request, not by the resumer.
            sink = promise.sink;
            plan = promise.plan;
            promise.persist = text.persist;
            // The resource now holds another request's leftovers, whose userdata root the move
            // would lose.
            resource_forget_userdata(resource);
            resource.run = std::move(mine);
            // A watcher that outlived its answer must not lend a state that has moved.
            watch_run_is(conn, mine_round, nullptr);
            const ComputeRefusal refused = compute_task_refusal(mine_round);
            if (mrb_unlikely(refused.status != 0)) {
                // A refused run never reached an answer, so its content type, file name and error
                // asset are dropped.
                resource_abandon(resource, resource.run);
                status = refused.status;
                have_body = false;
                body.clear();
                rhdrs.assign(refused.retry_after);
            } else if (mrb_unlikely(mine_round.wants_body)) {
                // A run that waited on octets carries no job, so the walk runs the node itself.
                // content_seen is set, so it does not stop there again.
                if (h1) {
                    if (conn.spill.fd >= 0) {
                        prep.rv.content_fd = conn.spill.fd;
                        prep.rv.content_len = conn.spill.written;
                        conn.spill.bound = true;
                    } else {
                        prep.rv.content = conn.body_hold.empty() ? nullptr : conn.body_hold.data();
                        prep.rv.content_len = conn.body_hold.size();
                    }
                    prep.rv.content_ready = true;
                    conn.run_wants_body = false;
                } else {
                    // A RST_STREAM may have closed the entry while the run was parked.
                    H2Stream *const owner =
                        conn.h2 != nullptr ? conn.h2->find(start.h2.stream_id) : nullptr;
                    if (owner != nullptr) {
                        if (owner->spill.fd >= 0) {
                            // The file is the stream's until close_stream drops the entry.
                            held.rv.content_fd = owner->spill.fd;
                            held.rv.content_len = owner->spill.written;
                            owner->spill.bound = true;
                        } else {
                            h2_content = std::move(owner->request_content);
                            owner->request_content.clear();
                            held.rv.content = h2_content.empty() ? nullptr : h2_content.data();
                            held.rv.content_len = h2_content.size();
                        }
                    }
                    held.rv.content_ready = true;
                }
                resource.run.wants_body = false;
                mine_round.wants_body = false;
                status = resource_resume(resource, {&body, &have_body, &rhdrs},
                                         {mine_round.answer_value, mine_round.job_what, 0});
            } else {
                // A watcher or a single task is one entry.
                const uint8_t owed = mine_round.jobs_owed != 0 ? mine_round.jobs_owed : 1;
                status = resource_resume(resource, {&body, &have_body, &rhdrs},
                                         {mine_round.answer_value, mine_round.job_what, owed});
            }
            // The answers were rooted while they waited. The round is read, so they are let go.
            for (mrb_value &a : mine_round.answer_value) {
                if (!mrb_nil_p(a)) {
                    mrb_gc_unregister(resource.mrb, a);
                    a = mrb_nil_value();
                }
            }
        }

        if (park >= 0) {
            // A watcher this round armed and never heard from still points at this frame, which
            // ends on the next line.
            for (const int slot : mine_round.w_slot) {
                if (slot >= 0)
                    watchers_drop_slot(conn, slot);
            }
            conn.park_drop(park);
            me.park = -1;
        }

        if (!h1) {
            // A resumed walk answers into this frame's locals.
            hpack.have_body = have_body;
            // RFC 9113 5.1: the peer may reset the stream while the run is parked.
            H2Stream *const entry = conn.h2->find(hq.stream_id);
            if (stopped && entry == nullptr)
                co_return 1;
            if (entry != nullptr)
                entry->parked = false;
            h2_after_run(conn, hq, hpack, status);
            const bool sent = h2_frame(conn, hq, *sink, hpack);
            if (stopped)
                h2_log(conn, {hq.facts, hq.target});
            co_return sent ? 1 : 0;
        }

        Round fr{conn,          block,         text.view,    text.viewlen,    text.off,
                 text.head_len, text.in_place, text.method,  text.method_len, text.path,
                 text.path_len, text.minor,    text.persist, text.head_only,  text.content_length,
                 text.lflags,   text.facts,    text.vals};
        const BoundAsk fask = {text.fields, text.nfields, text.spans, text.table, text.route,
                               plan,        *sink,        body,       rhdrs};
        BoundOut out_answer;
        out_answer.status = status;
        out_answer.have_body = have_body;
        out_answer.accept_gzip = prep.accept_gzip;
        if (mrb_unlikely(bound_finish(fr, fask, out_answer) == Took::kOwed)) {
            co_return 0;
        }
        const AnswerStep astep =
            spell_answer(fr, {*sink, plan, out_answer.status, out_answer.lent, out_answer.lent_len,
                              out_answer.answered, out_answer.have_body, out_answer.accept_gzip,
                              &block->index, body});
        // A stopped run answers long after the caller returned, so the access line is written
        // here.
        if (alog_.enabled) {
            log_access(alog_, {{static_cast<const char *>(conn.peer), conn.peer_len},
                               {text.method, text.method_len},
                               {text.path, text.path_len},
                               {text.vals.log_ref, text.vals.log_ref_len},
                               {text.vals.log_ua, text.vals.log_ua_len},
                               (astep.answered && !text.head_only) ? astep.body_len : 0,
                               out_answer.status,
                               text.lflags});
        }
        co_return out_answer.status;
    }
}

Http1::Took Http1::answer_bound(Round &round, const BoundAsk &request_ask, BoundOut &out_answer)
{
    const Bundle *const block = round.b;
    const flow::ReqFacts &facts = round.facts;
    const http::ReqValues &vals = round.vals;
    uint16_t status = 0;
    bool have_body = false;
    bool accept_gzip = false;
    BoundPrep prep;
    bound_prepare(round, request_ask, prep);
    ReqView &result = prep.rv;
    const size_t zc_min = prep.zc_min;
    accept_gzip = prep.accept_gzip;
    const RunAsk asked = {facts, &vals, &result, zc_min};
    const RunAnswer answer = {&request_ask.body, &have_body, &request_ask.rhdrs};
    status = resource_run(*block->res, asked, answer);
    out_answer.status = status;
    out_answer.have_body = have_body;
    out_answer.accept_gzip = accept_gzip;
    return bound_finish(round, request_ask, out_answer);
}

Http1::Preface Http1::h1_preface(Conn &conn, const char *data, size_t length, std::string &sink,
                                 size_t *consumed)
{
    conn.content_need = 0;
    const size_t seen = conn.carry.size();
    size_t i = 0;
    while (i < length && seen + i < kH2PrefaceLen && data[i] == kH2Preface[seen + i])
        i++;
    if (seen + i == kH2PrefaceLen) {
        conn.fresh = false;
        conn.carry.clear();
        if (!h2_begin(conn, sink))
            return Preface::kRefused;
        *consumed = i;
        return Preface::kH2;
    }
    if (i == length) {
        conn.carry.append(data, length);
        return Preface::kWait;
    }
    if (seen + i >= kH2PrefaceAnnounce) {
        static const unsigned char kGoaway[kH2FrameHeaderLen + 8] = {
            0, 0, 8, kH2Goaway, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, kH2ProtocolError};
        sink.append(reinterpret_cast<const char *>(kGoaway), sizeof(kGoaway));
        return Preface::kRefused;
    }
    conn.fresh = false;
    return Preface::kH1;
}

bool Http1::h1_upgrade_or_stream(Conn &conn, const H1Head &headers, std::string &sink, bool *lives)
{
    if (mrb_unlikely(headers.wants_ws)) {
        const AppSlot &wslot = apps_[conn.listener];
        RouteSpans wspans;
        const int writer =
            wslot.ws_table != nullptr
                ? wslot.ws_table->match(headers.path.data(), headers.path.size(), wspans)
                : -1;
        if (writer >= 0) {
            if (headers.ws_version != 13) {
                sink.append("HTTP/1.1 426 Upgrade Required\r\nDate: ");
                sink.append(date_, http::kDateLen);
                sink.append("\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n"
                            "Content-Length: 0\r\n\r\n");
                *lives = false;
                return true;
            }
            if (headers.facts.method != flow::Method::kGet || headers.ws_key == nullptr) {
                *lives = connection_fail(conn, 400, sink, headers.lflags);
                return true;
            }
            const WsUpgrade up{wslot,
                               writer,
                               headers.path,
                               wspans,
                               {headers.ws_key, headers.ws_key_len},
                               headers.headers,
                               headers.num_headers,
                               headers.vals,
                               {headers.rest, headers.rest_len}};
            *lives = ws_upgrade(conn, up, sink);
            return true;
        }
    }
    if (mrb_unlikely(apps_[conn.listener].sse_table != nullptr)) {
        const AppSlot &sslot = apps_[conn.listener];
        RouteSpans sspans;
        const int sse_route =
            sslot.sse_table->match(headers.path.data(), headers.path.size(), sspans);
        if (sse_route >= 0) {
            const SseBegin req{sslot,
                               sse_route,
                               headers.method,
                               headers.path,
                               sspans,
                               headers.headers,
                               headers.num_headers,
                               headers.minor,
                               headers.facts.method,
                               headers.vals,
                               headers.lflags};
            *lives = sse_begin(conn, req, sink);
            return true;
        }
    }
    return false;
}

// RFC 9112 5.2: obs-fold is refused with 400. picohttpparser reports a fold as a field with
// no name.
// RFC 9112 2.2: a bare LF is refused. A front end that reads it as part of a value and a
// server that splits the line disagree about where the message ends. That is request
// smuggling (RFC 9112 11.2).
static uint16_t
head_framing_status(const char *head, size_t length, const struct phr_header *fields, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (mrb_unlikely(fields[i].name_len == 0))
            return 400;
    }
    for (size_t i = 0; i < length; i++) {
        if (head[i] != '\n')
            continue;
        if (mrb_unlikely(i == 0 || head[i - 1] != '\r'))
            return 400;
    }
    return 0;
}

// Cold: once per refused body, so it stays out of feed_parse.
static uint16_t body_take_status(BodyTake took)
{
    switch (took) {
        case BodyTake::kTooLarge:
            return 413;
        case BodyTake::kNoSlot:
            return 503;
        case BodyTake::kFileFailed:
            return 500;
        default:
            return 400;
    }
}

bool Http1::feed_parse(Conn &conn, std::string_view incoming, Sink out_answer)
{
    const char *data = incoming.data();
    size_t length = incoming.size();
    std::string &sink = out_answer.bytes;
    Plan *const plan = out_answer.plan;
    if (conn.h2 != nullptr)
        return h2_feed(conn, incoming, out_answer);
    if (conn.fresh) {
        size_t consumed = 0;
        switch (h1_preface(conn, data, length, sink, &consumed)) {
            case Preface::kH2:
                return h2_feed(conn, {data + consumed, length - consumed}, out_answer);
            case Preface::kWait:
                return true;
            case Preface::kRefused:
                return false;
            case Preface::kH1:
                break;
        }
    }
    // The paths below return as soon as they take their octets, so a check under them would
    // never see a body in flight.
    if (kDebugBuild) {
        if (mrb_unlikely(!conn.mode_agrees())) {
            std::fprintf(stderr,
                         "webmachine: a connection says it is %s, and its pointers do not\n",
                         conn_mode_name(conn.mode));
            std::abort();
        }
        if (const char *const broken = conn.invariant_broken(); mrb_unlikely(broken != nullptr)) {
            std::fprintf(stderr, "webmachine: a connection that is %s broke a rule: %s\n",
                         conn_mode_name(conn.mode), broken);
            std::abort();
        }
    }

    if (conn.content_skip != 0) {
        const size_t take = std::min(conn.content_skip, length);
        conn.content_skip -= take;
        data += take;
        length -= take;
        if (length == 0)
            return true;
    }

    // RFC 9110 8.3: the first 512 octets are kept aside, because the body may be on its way
    // to a file. A contradiction is 415 at the first buffer.
    if (mrb_unlikely(!conn.sniff_type.empty() && !conn.sniff_done && length != 0)) {
        const size_t want = sniff::octets_needed();
        if (conn.sniff_head.size() < want) {
            const size_t room = want - conn.sniff_head.size();
            conn.sniff_head.append(data, std::min(length, room));
        }
        const sniff::Verdict value = sniff::check_declaration(conn.sniff_type, conn.sniff_head);
        if (mrb_unlikely(value == sniff::Verdict::kContradicts)) {
            drop_body(conn);
            return connection_fail(conn, 415, sink);
        }
        if (value == sniff::Verdict::kAgrees || conn.sniff_head.size() >= want)
            conn.sniff_done = true;
    }

    BodyTake took = BodyTake::kNone;
    switch (conn.body_to) {
        case Conn::Body::kNone:
            break;
        case Conn::Body::kMem:
            took = take_body(conn, MemWriter{&conn.body_hold}, data, length);
            break;
        case Conn::Body::kFile:
            took = take_body(conn, FileWriter{&conn.spill}, data, length);
            break;
        case Conn::Body::kChunkMem:
            took = take_chunked(conn, MemWriter{&conn.body_hold}, data, length);
            break;
        case Conn::Body::kChunkFile:
            took = take_chunked(conn, FileWriter{&conn.spill}, data, length);
            break;
    }
    switch (took) {
        case BodyTake::kNone:
            break;
        // A spilled body would keep its file open until the next accept into this slot.
        case BodyTake::kFailed:
            drop_body(conn);
            return false;
        // RFC 9110 15.5.14: 413. RFC 9110 15.6.4: no slot is load, 503. RFC 9110 15.6.1: a file
        // that failed is 500.
        case BodyTake::kTooLarge:
        case BodyTake::kNoSlot:
        case BodyTake::kFileFailed:
            drop_body(conn);
            return connection_fail(conn, body_take_status(took), sink);
        case BodyTake::kMore:
            return true;
        case BodyTake::kWhole:
            // The run reads the file, so the last write has to land first. spill_wrote makes the
            // round ready.
            if (conn.spill.fd >= 0) {
                conn.spill.ended = true;
                if (!conn.spill.drained())
                    break;
            }
            if (mrb_unlikely(conn.run_wants_body)) {
                Conn::Round *const round =
                    conn.park_at(conn.parked.co ? conn.parked.co.promise().park : -1);
                if (round != nullptr)
                    round->answer_ready = true;
                // No return: RFC 9112 9.3.2 answers in request order, so a pipelined request behind
                // the last octet waits in the carry.
            }
            break;
    }

    if (mrb_unlikely(conn.asset != nullptr)) {
        if (mrb_unlikely(conn.carry.size() + length > kAllHeaderBytes)) {
            conn.carry.clear();
            conn.content_skip = 0;
            conn.asset = nullptr;
            conn.become(ConnMode::kHead);
            return false;
        }
        conn.carry.append(data, length);
        return true;
    }

    if (mrb_unlikely(conn.websocket != nullptr))
        return ws_feed(conn.websocket, incoming, sink);
    if (mrb_unlikely(conn.sse != nullptr))
        return true;

    // RFC 9112 9.3.2: a request behind a parked run or an owed file waits in the carry.
    if (mrb_unlikely(conn.run_parked() ||
                     (conn.file != nullptr && conn.file->stage != FileStage::kNone))) {
        if (mrb_unlikely(conn.carry.size() + length > kAllHeaderBytes))
            return connection_fail(conn, 431, sink);
        conn.carry.append(data, length);
        return true;
    }

    const bool in_place = conn.carry.empty();
    const char *view = data;
    size_t viewlen = length;
    if (mrb_unlikely(!in_place)) {
        size_t grown = 0;
        if (mrb_unlikely(__builtin_add_overflow(conn.carry.size(), length, &grown))) {
            return connection_fail(conn, 431, sink);
        }
        conn.carry.append(data, length);
        view = conn.carry.data();
        viewlen = conn.carry.size();
    }

    size_t offset = 0;
    while (offset < viewlen) {
        // A new head says the last body has been read for the last time. An unbound file is
        // this request's body still arriving.
        if (mrb_unlikely(conn.spill.bound || conn.run_wants_body))
            conn.spill.close_file();
        // The run before this one may have asked for a body and answered without it. Left
        // standing, its file, hold and flag reach the next request.
        conn.run_wants_body = false;
        conn.body_hold.clear();
        conn.body_count = 0;
        const char *method;
        size_t method_len;
        const char *path;
        size_t path_len;
        int minor;
        struct phr_header headers[kPhrHeaderSlots];
        size_t num_headers = kPhrHeaderSlots;
        const int ret = phr_parse_request(view + offset, viewlen - offset, &method, &method_len,
                                          &path, &path_len, &minor, headers, &num_headers, 0);
        if (mrb_unlikely(ret == -2)) {
            const size_t rest = viewlen - offset;
            if (mrb_unlikely(rest > kAllHeaderBytes))
                return connection_fail(conn, 431, sink);
            if (in_place)
                conn.carry.assign(view + offset, rest);
            else
                conn.carry.erase(0, offset);
            return true;
        }
        if (mrb_unlikely(ret <= 0))
            return connection_fail(conn, 400, sink);
        if (mrb_unlikely(static_cast<size_t>(ret) > kAllHeaderBytes))
            return connection_fail(conn, 431, sink);
        {
            const uint16_t framing =
                head_framing_status(view + offset, static_cast<size_t>(ret), headers, num_headers);
            if (mrb_unlikely(framing != 0))
                return connection_fail(conn, framing, sink);
        }

        WireFacts window;
        flow::ReqFacts facts;
        http::ReqValues vals;
        facts.method = http::parse_method(method, method_len);
        for (size_t i = 0; i < num_headers; i++) {
            const struct phr_header &field = headers[i];
            if (http::header_switch({{field.name, field.name_len}, {field.value, field.value_len}},
                                    {facts, vals, i})) {
                wire_header_read({window, vals, i},
                                 {{field.name, field.name_len}, {field.value, field.value_len}});
            }
        }
        const uint8_t lflags = facts.no_track ? kLogNoTrack : 0;
        if (mrb_unlikely(window.out_error != 0))
            return connection_fail(conn, window.out_error, sink, lflags);
        // RFC 9112 6.1: both framings is a smuggling attempt.
        if (mrb_unlikely(window.have_te)) {
            if (mrb_unlikely(window.have_cl))
                return connection_fail(conn, 400, sink, lflags);
            // RFC 9112 6.1: a coding this server cannot read is 501.
            if (mrb_unlikely(window.te_unknown_coding))
                return connection_fail(conn, 501, sink, lflags);
            // RFC 9112 6.1: chunked is applied once and is the last coding.
            if (mrb_unlikely(window.te_chunked_count != 1 || !window.te_last_is_chunked))
                return connection_fail(conn, 400, sink, lflags);
        }
        if (mrb_unlikely(minor >= 1 && !window.have_host))
            return connection_fail(conn, 400, sink, lflags);
        bool persist = minor >= 1 ? !window.conn_close : window.conn_keep;
        const bool head_only = facts.method == flow::Method::kHead;
        // RFC 9112 6.6: the connection ends when the request carries content no node reads. The
        // head is spelled from persist, so the decision is made here.
        bool body_read = window.content_length == 0 && !window.have_te;
        size_t limit = apps_[conn.listener].max_body;
        size_t chunk_used = 0;
        if (mrb_unlikely(!body_read)) {
            // Measured: out of line this match cost 16 bytes here and 515 of its own, so it stays
            // inline. The route table is pure.
            const AppSlot &probe_slot = apps_[conn.listener];
            RouteSpans probe_spans;
            const int probe = probe_slot.table->match(path, path_len, probe_spans);
            if (probe >= 0) {
                const Bundle &probe_bundle = bundles_[probe_slot.base + static_cast<size_t>(probe)];
                body_read = probe_bundle.bound && probe_bundle.res->takes_body;
                // RFC 9110 15.5.14: the nearest limit answers, the resource's before the
                // application's.
                if (probe_bundle.bound && probe_bundle.res->max_body >= 0) {
                    limit = static_cast<size_t>(probe_bundle.res->max_body);
                }
            }
            if (!body_read)
                persist = false;
        }
        // RFC 9110 15.5.14: the check waits for the route probe, because the route can name a
        // nearer limit.
        if (mrb_unlikely(window.content_length > limit)) {
            return connection_fail(conn, 413, sink, lflags);
        }
        // A chunked body declares nothing, so the limit travels with the connection.
        conn.body_limit = limit;

        // RFC 9110 10.1.1: 100 Continue goes out before any octet of the body is read. When no
        // node reads the body, the final status answers instead. An unknown expectation is 417.
        // An HTTP/1.0 request carries no expectation.
        if (mrb_unlikely(window.expect_other))
            return connection_fail(conn, 417, sink, lflags);
        if (mrb_unlikely(window.expect_continue) && minor >= 1 && body_read &&
            (window.have_te || window.content_length != 0)) {
            sink.append("HTTP/1.1 100 Continue\r\n\r\n");
        }

        if (mrb_unlikely((window.up_ws && window.conn_upgrade) ||
                         apps_[conn.listener].sse_table != nullptr)) {
            const H1Head head = {{method, method_len},
                                 {path, path_len},
                                 minor,
                                 headers,
                                 num_headers,
                                 facts,
                                 vals,
                                 lflags,
                                 window.up_ws && window.conn_upgrade,
                                 window.ws_version,
                                 window.ws_key,
                                 window.ws_key_len,
                                 view + offset + static_cast<size_t>(ret),
                                 viewlen - offset - static_cast<size_t>(ret)};
            bool lives = true;
            if (h1_upgrade_or_stream(conn, head, sink, &lives))
                return lives;
        }

        {
            Round r{conn,     nullptr,   view,
                    viewlen,  offset,    static_cast<size_t>(ret),
                    in_place, method,    method_len,
                    path,     path_len,  minor,
                    persist,  head_only, window.content_length,
                    lflags,   facts,     vals};
            const Took asset_took = answer_from_assets(r, sink, plan);
            if (mrb_unlikely(asset_took != Took::kNo)) {
                offset = r.off;
                if (asset_took == Took::kClose)
                    return false;
                if (asset_took == Took::kOwed)
                    return true;
                continue;
            }
            if (mime_ != nullptr) {
                const Took from_disk = answer_from_docroot(r);
                if (from_disk != Took::kNo) {
                    offset = r.off;
                    return from_disk != Took::kClose;
                }
            }
        }

        const AppSlot &slot = apps_[conn.listener];
        RouteSpans spans;
        const int route = slot.table->match(path, path_len, spans);
        const Bundle *block = nullptr;
        const std::array<uint16_t, 600> *idx = &index_;
        uint16_t status;
        bool have_body = false;
        bool answered = false;
        const char *lent = nullptr;
        size_t lent_len = 0;
        bool accept_gzip = false;
        if (mrb_unlikely(route < 0)) {
            status = 404;
        } else {
            block = &bundles_[slot.base + static_cast<size_t>(route)];
            idx = &block->index;
            if (mrb_likely(block->bound)) {
                const size_t head_len = static_cast<size_t>(ret);
                const size_t body_here = viewlen - offset - head_len;
                // A spilled request is re-parsed with an empty carry behind the head, and its body
                // is complete all the same.
                const size_t body_have = conn.spill.fd >= 0 ? conn.spill.written : body_here;
                // RFC 9112 9.3.2: the next request may follow the last octet of this one, so a
                // declared length bounds the take.
                const size_t body_octets =
                    window.content_length != 0 && body_here > window.content_length
                        ? window.content_length
                        : body_here;
                // RFC 9110 6.4: only content_types_accepted, create_path and process_post read a
                // body. A resource without them waits for nothing. RFC 9110 8.3: the claim is in
                // the head and the octets arrive after it, so the type is kept for the first
                // buffer.
                if (mrb_unlikely(!block->res->sniff_types.empty()) &&
                    vals.content_type != nullptr) {
                    const std::string_view claim{vals.content_type, vals.content_type_len};
                    if (sniff::was_asked_for(block->res->sniff_types, claim)) {
                        conn.sniff_type.assign(claim);
                        conn.sniff_head.clear();
                        conn.sniff_done = false;
                        // The first octets usually arrive with the head and never pass the feed's
                        // body switch, so the check starts here.
                        const size_t want = sniff::octets_needed();
                        conn.sniff_head.assign(view + offset + head_len,
                                               body_here < want ? body_here : want);
                        const sniff::Verdict value =
                            sniff::check_declaration(conn.sniff_type, conn.sniff_head);
                        if (mrb_unlikely(value == sniff::Verdict::kContradicts)) {
                            return connection_fail(conn, 415, sink, lflags);
                        }
                        if (value == sniff::Verdict::kAgrees || conn.sniff_head.size() >= want) {
                            conn.sniff_done = true;
                        }
                    }
                }
                // RFC 9112 7.1: a chunked body starts in memory and moves to a file when the count
                // says so.
                if (mrb_unlikely(window.have_te) && mrb_likely(block->res->takes_body)) {
                    conn.chunk = {};
                    // RFC 9112 7.1.2: the decoder drops the trailer section.
                    conn.chunk.consume_trailer = 1;
                    conn.body_count = 0;
                    // RFC 9112 7.1: the framing budget is per body, and a kept-alive connection
                    // carries many bodies.
                    conn.chunk_framing = 0;
                    // RFC 9112 7.1.1: the framing walk starts at a size line once per body.
                    conn.chunk_scan = Conn::ChunkScan::kSize;
                    conn.chunk_need = 0;
                    conn.chunk_after = 0;
                    conn.chunk_line.clear();
                    conn.body_hold.clear();
                    conn.body_to = Conn::Body::kChunkMem;
                    conn.run_wants_body = true;
                    const char *content_start = view + offset + head_len;
                    size_t clen = body_here;
                    const BodyTake read_bytes =
                        take_chunked(conn, MemWriter{&conn.body_hold}, content_start, clen);
                    chunk_used = body_here - clen;
                    if (mrb_unlikely(read_bytes != BodyTake::kMore &&
                                     read_bytes != BodyTake::kWhole)) {
                        drop_body(conn);
                        return connection_fail(conn, body_take_status(read_bytes), sink, lflags);
                    }
                    conn.run_wants_body = read_bytes != BodyTake::kWhole;
                } else if (window.content_length != 0 && mrb_likely(block->res->takes_body) &&
                           (body_have < window.content_length || block->res->saves_body)) {
                    // save: true takes this branch with the body already whole, so the count is the
                    // body's own and not the buffer's.
                    const size_t have =
                        body_have < window.content_length ? body_have : window.content_length;
                    conn.content_need = window.content_length - have;
                    // A callback that declared save: true gets its body in a file whatever the
                    // size, so request.body.save is a link and never a second write.
                    if (window.content_length >= kBodySpill || block->res->saves_body) {
                        // RFC 9110 15.6.4: no slot is 503. RFC 9110 15.6.1: no file is 500.
                        const SpillOpen opened = conn.spill.open_file();
                        if (mrb_unlikely(opened != SpillOpen::kOpen)) {
                            return connection_fail(conn, opened == SpillOpen::kNoSlot ? 503 : 500,
                                                   sink, lflags);
                        }
                        if (mrb_unlikely(!conn.spill.take(view + offset + head_len, body_octets))) {
                            conn.spill.close_file();
                            return connection_fail(conn, 500, sink, lflags);
                        }
                        // A destination is named only while octets are owed. A whole body still
                        // waits for its write to land, and spill_wrote says when.
                        if (conn.content_need != 0)
                            conn.body_to = Conn::Body::kFile;
                        else
                            conn.spill.ended = true;
                    } else {
                        // The body cannot stay behind the head in the carry, because the carry is
                        // where a pipelined request waits.
                        conn.body_hold.reserve(window.content_length);
                        conn.body_hold.assign(view + offset + head_len, body_octets);
                        conn.body_to = Conn::Body::kMem;
                    }
                    conn.run_wants_body = true;
                }
                // Measured: giving this frame to every bound resource broke response.file in
                // thirteen bintests, so the gate stays what a resource declared.
                if (mrb_unlikely(block->res->compute != 0 || block->res->watch != 0 ||
                                 block->res->value_jobs != 0 || block->res->value_watch != 0 ||
                                 conn.run_wants_body)) {
                    const size_t past = head_len + (conn.run_wants_body ? body_octets : chunk_used);
                    const BoundStart start = {block,
                                              view + offset,
                                              view,
                                              viewlen,
                                              offset + past,
                                              head_len,
                                              method,
                                              method_len,
                                              path,
                                              path_len,
                                              window.content_length,
                                              headers,
                                              num_headers,
                                              spans,
                                              slot.table,
                                              facts,
                                              vals,
                                              route,
                                              minor,
                                              lflags,
                                              in_place,
                                              persist,
                                              head_only};
                    const ComputeRound round =
                        start_compute_round(conn, start, &sink, plan, offset);
                    if (mrb_unlikely(round == ComputeRound::kParked))
                        return true;
                    if (mrb_unlikely(round == ComputeRound::kClosed))
                        return false;
                    continue;
                }
                Round br{conn,     block,    view,    viewlen,    offset + head_len,
                         head_len, in_place, method,  method_len, path,
                         path_len, minor,    persist, head_only,  window.content_length,
                         lflags,   facts,    vals};
                BoundOut bound_out;
                const BoundAsk basked = {headers, num_headers, spans, slot.table, route,
                                         plan,    sink,        body_, rhdrs_};
                if (mrb_unlikely(answer_bound(br, basked, bound_out) == Took::kOwed)) {
                    have_body = false;
                    return true;
                }
                status = bound_out.status;
                have_body = bound_out.have_body;
                answered = bound_out.answered;
                lent = bound_out.lent;
                lent_len = bound_out.lent_len;
                accept_gzip = bound_out.accept_gzip;
            } else {
                // RFC 9110 12.5.1: the fold left this resource one media type, so the match is
                // asked here and never in the VM.
                if (mrb_unlikely(facts.has_accept && vals.accept != nullptr)) {
                    if (http::accept_is_exact({vals.accept, vals.accept_len}, block->accept_type)) {
                        facts.has_accept = false;
                    } else {
                        facts.plain = false;
                        facts.accept_ok =
                            http::choose_media_type(
                                {{&block->accept_type, 1}, {vals.accept, vals.accept_len}}) >= 0;
                    }
                }
                const size_t method_index = static_cast<size_t>(facts.method);
                status = flow::answer(facts, {block->konst.per_method[method_index],
                                              block->konst.shortcut[method_index]});
            }
        }

        Round ar{conn,
                 block,
                 view,
                 viewlen,
                 offset + static_cast<size_t>(ret),
                 static_cast<size_t>(ret),
                 in_place,
                 method,
                 method_len,
                 path,
                 path_len,
                 minor,
                 persist,
                 head_only,
                 window.content_length,
                 lflags,
                 facts,
                 vals};
        const AnswerStep astep = spell_answer(
            ar, {sink, plan, status, lent, lent_len, answered, have_body, accept_gzip, idx, body_});
        if (alog_.enabled) {
            log_access(alog_, {{static_cast<const char *>(conn.peer), conn.peer_len},
                               {method, method_len},
                               {path, path_len},
                               {vals.log_ref, vals.log_ref_len},
                               {vals.log_ua, vals.log_ua_len},
                               (astep.answered && !head_only) ? astep.body_len : 0,
                               status,
                               lflags});
        }

        offset += static_cast<size_t>(ret);
        // RFC 9112 6.6: content no node asked for ends the connection. RFC 9110 9.3.1: content
        // behind a request nobody parsed is where smuggling lives.
        if (mrb_unlikely(!body_read)) {
            conn.carry.clear();
            conn.content_skip = 0;
            conn.content_need = 0;
            return false;
        }
        // A body that went to a file is already out of the buffer. Counting it again would make
        // the next head look like this body.
        if (window.content_length != 0 && conn.spill.fd < 0) {
            const size_t avail = viewlen - offset;
            const size_t skip = std::min(window.content_length, avail);
            offset += skip;
            conn.content_skip = window.content_length - skip;
        }
        offset += chunk_used;
        if (mrb_unlikely(!persist)) {
            conn.carry.clear();
            conn.content_skip = 0;
            return false;
        }
    }
    if (mrb_unlikely(!in_place))
        conn.carry.clear();
    return true;
}

bool Http1::ws_upgrade(Conn &conn, const WsUpgrade &upgrade, std::string &sink)
{
    const AppSlot &slot = upgrade.slot;
    const int route = upgrade.route;
    const std::string_view path = upgrade.path;
    const RouteSpans &spans = upgrade.spans;
    const void *hdrs = upgrade.hdrs;
    const size_t nhdr = upgrade.nhdr;
    const http::ReqValues &vals = upgrade.vals;
    char accept[28];
    if (!ws::accept_key_compute(upgrade.key.data(), upgrade.key.size(), accept))
        return connection_fail(conn, 400, sink);

    const WsResource *resource = ws_res_[slot.ws_base + static_cast<size_t>(route)];

    ReqView result;
    result.tls = apps_[conn.listener].tls;
    result.request_target = path.data();
    result.request_target_len = path.size();
    result.path_len = http::path_only(path.data(), path.size());
    result.method = flow::Method::kGet;
    result.table = slot.ws_table;
    result.route = route;
    result.spans = &spans;
    result.fields = hdrs;
    result.field_count = nhdr;
    result.values = &vals;
    request_bind(&result);
    std::string proto;
    uint16_t refuse_status = 0;
    WsConn *wsc = ws_admit(resource, elog_.enabled ? &elog_ : nullptr, {proto, refuse_status});
    request_bind(nullptr);
    if (wsc == nullptr) {
        return connection_fail(conn, refuse_status == 0 ? 403 : refuse_status, sink);
    }

    wsdeflate::Params dparams;
    std::string ext_answer;
    if (ws_wants_deflate(resource)) {
        const struct phr_header *fields = static_cast<const struct phr_header *>(hdrs);
        for (size_t i = 0; i < nhdr && !dparams.on; i++) {
            if (!http::tok_eq({fields[i].name, fields[i].name_len}, "sec-websocket-extensions"))
                continue;
            wsdeflate::negotiate({fields[i].value, fields[i].value_len}, {dparams, ext_answer});
        }
    }

    sink.append("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: "
                "Upgrade\r\nSec-WebSocket-Accept: ");
    sink.append(accept, sizeof(accept));
    if (!proto.empty()) {
        sink.append("\r\nSec-WebSocket-Protocol: ").append(proto);
    }
    if (dparams.on)
        sink.append("\r\nSec-WebSocket-Extensions: ").append(ext_answer);
    sink.append("\r\n\r\n");

    ws_open(wsc, dparams);
    conn.websocket = wsc;
    conn.become(ConnMode::kWs);
    conn.carry.clear();
    conn.content_skip = 0;
    if (!upgrade.rest.empty())
        return ws_feed(conn.websocket, upgrade.rest, sink);
    return true;
}

void Http1::log_sse(Logger &logger, const Conn &conn, const SseLine &line)
{
    if (!logger.enabled)
        return;
    const std::string_view method = line.method;
    const std::string_view path = line.path;
    const http::ReqValues &vals = line.vals;
    const uint8_t lflags = line.lflags;
    const uint16_t status = line.status;
    log_access(logger, {{static_cast<const char *>(conn.peer), conn.peer_len},
                        method,
                        path,
                        {vals.log_ref, vals.log_ref_len},
                        {vals.log_ua, vals.log_ua_len},
                        0,
                        status,
                        lflags});
}

bool Http1::sse_begin(Conn &conn, const SseBegin &request_view, std::string &sink)
{
    const AppSlot &slot = request_view.slot;
    const int route = request_view.route;
    const std::string_view method = request_view.method;
    const std::string_view path = request_view.path;
    const RouteSpans &spans = request_view.spans;
    const void *hdrs = request_view.hdrs;
    const size_t nhdr = request_view.nhdr;
    const int minor = request_view.minor;
    const flow::Method m = request_view.m;
    const http::ReqValues &vals = request_view.vals;
    const uint8_t lflags = request_view.lflags;
    if (mrb_unlikely(m != flow::Method::kGet)) {
        log_sse(alog_, conn, {method, path, vals, 405, lflags});
        sink.append("HTTP/1.1 405 Method Not Allowed\r\nDate: ");
        sink.append(date_, http::kDateLen);
        sink.append("\r\nAllow: GET\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        return false;
    }
    if (mrb_unlikely(minor < 1)) {
        log_sse(alog_, conn, {method, path, vals, 505, lflags});
        sink.append("HTTP/1.1 505 HTTP Version Not Supported\r\nDate: ");
        sink.append(date_, http::kDateLen);
        sink.append("\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        return false;
    }

    ReqView result;
    result.tls = apps_[conn.listener].tls;
    result.request_target = path.data();
    result.request_target_len = path.size();
    result.path_len = http::path_only(path.data(), path.size());
    result.method = flow::Method::kGet;
    result.table = slot.sse_table;
    result.route = route;
    result.spans = &spans;
    result.fields = hdrs;
    result.field_count = nhdr;
    result.values = &vals;
    request_bind(&result);
    uint16_t refused = 0;
    SseStream *text = sse_open(sse_res_[slot.sse_base + static_cast<size_t>(route)],
                               elog_.enabled ? &elog_ : nullptr, refused);
    request_bind(nullptr);
    if (text == nullptr) {
        // RFC 9110 15.5.4: a stream the app would not open is 403 unless the app named a status.
        const uint16_t status = refused == 0 ? 403 : refused;
        log_sse(alog_, conn, {method, path, vals, status, lflags});
        return connection_fail(conn, status, sink, lflags);
    }

    log_sse(alog_, conn, {method, path, vals, 200, lflags});
    sink.append("HTTP/1.1 200 OK\r\nDate: ");
    sink.append(date_, http::kDateLen);
    sink.append("\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
                "Transfer-Encoding: chunked\r\n\r\n");
    conn.sse = text;
    conn.become(ConnMode::kSse);
    conn.carry.clear();
    conn.content_skip = 0;
    return true;
}
} // namespace webmachine
