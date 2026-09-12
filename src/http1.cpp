#include "webmachine.hpp"

#include "ring.hpp"

#include <picohttpparser.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace webmachine
{
namespace
{
// RFC 9110 7.6.1: Connection is a token list - a substring match would
// accept "not-close".
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

// RFC 9112: what the framer reads out of the head - the fields 9110's
// header_switch hands back because their meaning is the connection's,
// not the resource's.
struct WireFacts {
    size_t content_length = 0;
    const char *ws_key = nullptr;
    size_t ws_key_len = 0;
    int ws_version = 0;
    uint16_t out_error = 0;
    bool have_cl = false;
    bool have_te = false;
    bool te_chunked = false;
    bool have_host = false;
    bool conn_close = false;
    bool conn_keep = false;
    bool up_ws = false;
    bool conn_upgrade = false;
};

// RFC 9112 / RFC 6455: host(4) referer/upgrade(7) connection/user-agent(10)
// content-length(14) sec-websocket-key/transfer-encoding(17)
// sec-websocket-version(21).
constexpr size_t kWireLengths[] = {4, 7, 10, 14, 17, 21};
constexpr uint32_t kWireLengthMask =
    http::lengths_mask(kWireLengths, sizeof(kWireLengths) / sizeof(kWireLengths[0]));

// Where one request's framing facts are being filled: the facts, the
// values that point back into the head, and the index of the field being
// read - the same shape http::FactSink has for the 9110 facts.
struct WireSink {
    WireFacts &window;
    http::ReqValues &vals;
    size_t index;
};

// RFC 9112 6.1/6.3, 7.6.1, RFC 6455 4.1: one such field.
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
                // RFC 9112 6.1: chunked is the only coding this server reads,
                // and it has to be the last one. Anything else is 501.
                window.te_chunked = http::tok_eq({value, value_length}, "chunked");
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
        default:
            break;
    }
}

// RFC 9112 3/9.3: the head that one bound run spelled for itself. Its status,
// the Date line for this second, its own Content-Type and field lines,
// this connection's framing, and a length where it declares one. No
// prebuilt head can take that shape.
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

// And here it is spelled, byte by byte.
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

// One of build_variants' three spellings, its date offset noted.
void Http1::build_one_variant(Resp &round, Prebuilt bytes)
{
    round.bytes.clear();
    char line[16];
    line[0] = static_cast<char>('0' + bytes.status / 100);
    line[1] = static_cast<char>('0' + (bytes.status / 10) % 10);
    line[2] = static_cast<char>('0' + bytes.status % 10);
    line[3] = '\0';
    round.bytes.append("HTTP/1.1 ").append(line).append(" ").append(http::reason(bytes.status));
    round.bytes.append("\r\nDate: ");
    round.date_off = round.bytes.size();
    round.bytes.append(bytes.date)
        .append("\r\n")
        .append(bytes.conn)
        .append(bytes.extra)
        .append(bytes.body);
}

// One prebuilt head with its trailing `cut` bytes left off.
void Http1::copy_without_tail(const Resp &src, Resp &dst, size_t cut)
{
    dst.bytes.assign(src.bytes, 0, src.bytes.size() - cut);
    dst.date_off = src.date_off;
}

// A 200 or 500 head that stops before Content-Length, for a body the run
// has yet to produce. `enc` carries whatever Vary/Content-Encoding applies.
void Http1::build_open_prefix(Resp &round, OpenPrefix bytes)
{
    round.bytes.clear();
    round.bytes.append(bytes.status_line).append("\r\nDate: ");
    round.date_off = round.bytes.size();
    round.bytes.append(kDatePlaceholder)
        .append("\r\n")
        .append(bytes.conn)
        .append(bytes.extra)
        .append(bytes.enc);
}

// RFC 9112 9.3: one status prebuilt in all three connection spellings.
void Http1::build_variants(Variants &value, Prebuilt bytes)
{
    bytes.conn = "";
    build_one_variant(value.plain, bytes);
    bytes.conn = "Connection: keep-alive\r\n";
    build_one_variant(value.keep, bytes);
    bytes.conn = "Connection: close\r\n";
    build_one_variant(value.close, bytes);
}

// And the same head, open, in the same three.
void Http1::build_open_prefixes(Variants &value, OpenPrefix bytes)
{
    bytes.conn = "";
    build_open_prefix(value.plain, bytes);
    bytes.conn = "Connection: keep-alive\r\n";
    build_open_prefix(value.keep, bytes);
    bytes.conn = "Connection: close\r\n";
    build_open_prefix(value.close, bytes);
}

// RFC 9110 15: one status into the shared store, date offset kept - and
// beside it the same answer without `body`, which is where an error that
// has a page to show puts its own Content-Type and Content-Length (#210).
void Http1::build_status(uint16_t status, StatusText status_text)
{
    Variants value;
    build_variants(value, {status, status_text.extra, status_text.body, kDatePlaceholder});
    Variants bytes;
    build_variants(bytes, {status, status_text.extra, "", kDatePlaceholder});
    index_[status] = static_cast<uint16_t>(store_.size());
    store_.push_back(std::move(value));
    store_prefix_.push_back(std::move(bytes));
}

// RFC 9110 5.6.7: the 29 date bytes, once a second, in place.
void Http1::patch_date(Variants &value, const char *core)
{
    std::memcpy(value.plain.bytes.data() + value.plain.date_off, core, kDateLen);
    std::memcpy(value.keep.bytes.data() + value.keep.date_off, core, kDateLen);
    std::memcpy(value.close.bytes.data() + value.close.date_off, core, kDateLen);
}

// RFC 9110: one route's whole voice - its 200 in every shape, its Allow
// (10.2.1), its negotiated type (8.3), its gzip decision, its h2 blocks.
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
    // The 200 without its tail - no Content-Length, no body. A dynamic body
    // needs it because its length is not known until the run returns; a konst
    // body needs it because the prebuilt 200 carries the body inside the
    // buffer whose Date stamp_variants patches every second, and a body that
    // is lent rather than copied must not sit in bytes that move.
    {
        const size_t cut = ok_tail.size();
        copy_without_tail(accepted.plain, block.ok_prefix.plain, cut);
        copy_without_tail(accepted.keep, block.ok_prefix.keep, cut);
        copy_without_tail(accepted.close, block.ok_prefix.close, cut);
    }
    block.index[200] = static_cast<uint16_t>(store_.size());
    {
        // The twin of every store_ push: store_prefix_ is addressed by the
        // same index, so the two vectors have to grow together (#210).
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
        // RFC 9110 15.5.6: the 405 page keeps its Allow, and adds the page's
        // own Content-Type behind it.
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

// One app, one listener - the shape everything but a multi-app file has.
Http1::Http1(const RouteTable &table, const Resource *const *resources, size_t nroutes,
             Assets *assets)
    : assets_(assets)
{
    const AppInput one{&table, resources, nroutes};
    http1_build_all(&one, 1);
}

// Every response every route of every app can speak, built once.
Http1::Http1(const AppInput *apps, size_t napps, Assets *assets) : assets_(assets)
{
    http1_build_all(apps, napps);
}

// RFC 9110 15: one status' h1 spellings and its h2 block, the first time
// the flow graph or a framer names it.
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

// RFC 9110 15: the status supply, the bundles and the asset blocks, at setup.
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
    // response.file answers out of this store too, and index_ defaults to slot
    // 0 - an absent status would quietly spell whatever lives there.
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

// A pack built again while this one serves. The entries are new objects
// in a new mapping, so the h2 blocks are built for them the way the
// constructor built them for the pack this replaces.
void Http1::swap_assets(Assets *assets)
{
    assets_ = assets;
    if (assets_ == nullptr)
        return;

    h2_build_asset_shared();
    for (AssetEntry &e : assets_->entries())
        h2_build_asset_blocks(e);
}

// RFC 9110 5.6.7: the wall-clock second changed - patch every prebuilt date.
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
        // RFC 9110 6.6.1: the Date is the time the message was made, so
        // Every head that goes on the wire is stamped - ok_prefix included,
        // which serves the konst body as well as a dynamic one.
        patch_date(b.ok_prefix, core);
        if (b.gzip_ok) {
            patch_date(b.ok_prefix_vary, core);
            patch_date(b.ok_prefix_gzip, core);
        }
        if (b.bound)
            patch_date(b.err_prefix, core);
    }
}

// RFC 9110 8.6: prefix + hand-spelled Content-Length + (unless HEAD) the body.
void Http1::answer_assemble(std::string &sink, const Assembled &asset_ask)
{
    sink.append(asset_ask.prefix.bytes);
    char content_length[40];
    sink.append(content_length, http::spell_content_length(content_length, asset_ask.body.size()));
    if (!asset_ask.head_only)
        sink.append(asset_ask.body);
}

// RFC 9110 12.5.3/12.5.5: identity or gzip for a dynamic 200, and the Vary
// that says the resource varies either way.
void Http1::assemble_dynamic(const DynamicBody &dynamic_body, std::string &sink)
{
    bool use_gzip = false;
    if (dynamic_body.may_gzip) {
        char content_length[40];
        const size_t cl_len = http::spell_content_length(content_length, dynamic_body.body.size());
        if (dynamic_body.prefix_id.bytes.size() + cl_len + dynamic_body.body.size() >=
            kCompressFloor) {
            use_gzip = gzip::compress(dynamic_body.body, gz_body_);
        }
    }
    if (use_gzip)
        answer_assemble(sink, {dynamic_body.prefix_gz, gz_body_, dynamic_body.head_only});
    else
        answer_assemble(sink, {dynamic_body.prefix_id, dynamic_body.body, dynamic_body.head_only});
}

// RFC 9112: wire invalidity - framing trust is gone, the connection ends.
// #210: the error pages render in a VM this layer does not own. Called
// once, after the bundles exist; a caller that never calls it keeps the
// bodyless statuses (#173: bytes in, bytes out, no VM required).
void Http1::open_error_assets(mrb_state *mrb, Assets *error_assets)
{
    error_assets_ = error_assets;
    err_pages_.open(mrb, error_assets, &elog_);
}

// RFC 9110 15: the error answer - the prebuilt status line and Date, then
// the page rendered for this request. RFC 9110 9.3.2: a HEAD carries the
// Content-Length a GET would have sent, and no body.
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

// RFC 9110 6.3 / RFC 9111: a mounted archive answers this target on its
// own - conditional requests, ranges and refusals included - without the
// flow or the VM. /error_assets/ is resolved against the error archive,
// which is always mounted; everything else against --assets.
Http1::Took Http1::answer_from_assets(Round &round, std::string &sink, Plan *plan)
{
    Assets *tier = assets_;
    const char *apath = round.path;
    size_t alen = round.path_len;
    char abuf[kMaxHead];
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
    AssetEntry *asset_entry = tier->find(apath, alen);
    if (asset_entry == nullptr)
        return Took::kNo;
    const uint16_t as = tier->entry_verdict(*asset_entry, {round.facts, round.vals});
    const AssetStep step =
        asset_step(*asset_entry, {as, round.head_only, round.facts.method, round.vals});
    const Assets::ConnectionOption conn =
        round.minor >= 1 ? (round.persist ? Assets::kNoConnectionField : Assets::kConnClose)
                         : (round.persist ? Assets::kKeepAlive : Assets::kConnClose);
    // #210: a refusal this tier owns is a 4xx like any other, and a 4xx
    // explains itself. The page is the one every 4xx sends; what differs is
    // what the tier spells around it - a 405's Allow, a 406's Vary, a 416's
    // Content-Range - so the tier writes the head and is handed the body to
    // declare in it.
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
    head.conn = conn;
    head.date = date_;
    head.unix_seconds = sec_;
    head.first_byte_pos = step.first_byte_pos;
    head.last_byte_pos = step.first_byte_pos + step.content_length - 1;
    head.body_type = ectype;
    head.body_len = eblen;
    switch (step.head) {
        case AssetStep::HeadKind::kRefusal: {
            // 412 and 501 carry no field of this tier's own, so they are spelled
            // the way every other status of theirs is.
            const Variants &pv = prefixes(step.status_code);
            const Variants &sv = variants(step.status_code);
            const bool plain = round.minor >= 1;
            const ErrorPages::Fields none;
            const Resp &prefix = plain ? (round.persist ? pv.plain : pv.close)
                                       : (round.persist ? pv.keep : pv.close);
            const Resp &bodyless = plain ? (round.persist ? sv.plain : sv.close)
                                         : (round.persist ? sv.keep : sv.close);
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
    // The head this answered is consumed here, not by the caller -
    // the caller only learns r.off once the round is taken.
    round.off += round.head_len;
    if (round.content_length != 0) {
        const size_t avail = round.viewlen - round.off;
        const size_t skip = round.content_length < avail ? round.content_length : avail;
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

// RFC 9110 6.3: the run named a file rather than spelling a body, and
// opening one is disk work that does not belong in a reactor step. The
// framing is copied onto the connection, the reactor drives openat2/
// statx/read through the ring, and `spell_next_round` puts the result on the wire.
// A name this process already refused takes the same 404 the kernel's
// own refusal would, spelled here since no ring trip is owed.
bool Http1::answer_from_file(Round &round, uint16_t status, const std::string &rhdrs)
{
    WantedFile wanted;
    if (!resource_file_wanted(*round.b->res, wanted) || status != 200)
        return false;

    Conn &conn = round.st;
    // resource_run never lends a body a run also named a file for (see the
    // O18 body handler), so nothing is lent here - zc_release() still runs,
    // for its h2-backlog drain.
    conn.zc_release();
    if (conn.file == nullptr)
        conn.file = new Conn::FileXfer();
    conn.file->pathname.assign(wanted.name);
    conn.file->field_lines = rhdrs;
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
    // RFC 9110 12.5.1: which form a refusal takes is the caller's Accept,
    // and a refusal can land long after this round - so it is decided here,
    // while the request is still in hand.
    conn.file->err_media =
        err_pages_.media_pick_for_status(404, round.vals.accept, round.vals.accept_len);
    conn.file->stage = FileStage::kNamed;
    if (wanted.bad)
        file_reject(conn);
    file_named_tail(round);
    return true;
}

// What every named file owes the connection once the answer is the ring's:
// the request body this round will never read is skipped, and what the
// parse read past this request is carried to the next one.
void Http1::file_named_tail(Round &round)
{
    Conn &conn = round.st;
    size_t offset = round.off;
    if (round.content_length != 0) {
        const size_t avail = round.viewlen - offset;
        const size_t skip = round.content_length < avail ? round.content_length : avail;
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

// RFC 9110 4.2.1: the target names a file under the docroot, and this is
// the tier that answers it - with no app, no route and no VM. The
// decision is the graph's, folded: GET and HEAD answer, anything else is
// 405, a directory takes its index.html, and what is not there is 404.
//
// It is the file machine underneath, the same one response.file drives:
// openat2 beneath the docroot fd, statx, If-Modified-Since, the head
// spelled per file. What this adds is the name and the media type.
Http1::Took Http1::answer_from_docroot(Round &round)
{
    if (docroot_fd() < 0 || mime_ == nullptr)
        return Took::kNo;

    Conn &conn = round.st;
    const bool readable =
        round.facts.method == flow::Method::kGet || round.facts.method == flow::Method::kHead;

    // The path a client wrote, without its leading slash and without a
    // query. A directory takes its own index.html, as the asset tier does.
    size_t length = round.path_len;
    for (size_t i = 0; i < length; i++) {
        if (round.path[i] == '?') {
            length = i;
            break;
        }
    }
    std::string name;
    if (length > 1)
        name.assign(round.path + 1, length - 1);
    if (name.empty() || name.back() == '/')
        name.append("index.html");

    // A name this process can refuse without asking the kernel. openat2
    // with RESOLVE_BENEATH would refuse the same ones, and a ring trip
    // that can only end in 404 is a ring trip nobody owes.
    bool bad = name.find('\0') != std::string::npos;
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
    // Nothing is parsed on this path, so there is no Accept to weigh and no
    // target to name: the page for the status, and that is all it can say.
    const ErrorPages::Fields field;
    spell_error({prefixes(code).close, variants(code).close, code,
                 err_pages_.media_pick_for_status(code, nullptr, 0), field, false},
                out_answer);
    conn.carry.clear();
    conn.content_skip = 0;
    conn.content_need = 0;
    return false;
}

// The sink's uncovered tail since the last claim, as one external segment -
// every site that splices something else into the plan claims this head
// first, so what follows lands at the right offset on the wire.
void Http1::sink_claim(Conn &conn, const std::string &sink, Plan &plan)
{
    if (sink.size() > conn.zc_covered) {
        const size_t head = sink.size() - conn.zc_covered;
        plan.iov[plan.iovlen++] = Plan::Seg{nullptr, conn.zc_covered, head};
        plan.byte_total += head;
    }
    conn.zc_covered = sink.size();
}

// A lent body splits the sink, so whatever the parse appended after it
// still has to be claimed - and it returns down a dozen paths, so the plan
// is closed here, once, on all of them.
bool Http1::connection_feed(Conn &conn, std::string_view data, Sink out_answer)
{
    std::string &sink = out_answer.bytes;
    Plan *const plan = out_answer.plan;
    const bool accepted = feed_parse(conn, data, out_answer);
    if (mrb_unlikely(conn.zc_split) && plan != nullptr)
        sink_claim(conn, sink, *plan);
    return accepted;
}

// RFC 9110 8.6: the body the run lent, delivered as an external segment
// over its own frozen String - the door http1's mmap'd assets already use.
// The sink bytes it splits are claimed on either side of it by offset.
void Http1::body_lend(Conn &conn, std::string &sink, Lending lend)
{
    Plan &plan = lend.plan;
    sink_claim(conn, sink, plan);
    plan.iov[plan.iovlen++] = Plan::Seg{lend.body.data(), 0, lend.body.size()};
    plan.byte_total += lend.body.size();
    conn.zc_split = true;
}

// RFC 9112 9.3: a file answer of its own status, in this connection's
// spelling - and with the page that status has.
//
// Every refusal wears its page, whatever served it. The graph has one
// 404, and a file that is not there is that 404: the same body a
// resource answering g7 with false would send. This used to take the
// bodyless status out of the shared store, so a docroot miss answered
// Content-Length: 0 while the same miss on a pack answered a page.
void Http1::file_prebuilt(Conn &conn, uint16_t status_code)
{
    const Variants &sv = variants(status_code);
    const Resp &bodyless = conn.file->minor >= 1 ? (conn.file->persist ? sv.plain : sv.close)
                                                 : (conn.file->persist ? sv.keep : sv.close);
    conn.file->head.clear();
    if (status_code >= 400) {
        const Variants &pv = prefixes(status_code);
        const Resp &prefix = conn.file->minor >= 1 ? (conn.file->persist ? pv.plain : pv.close)
                                                   : (conn.file->persist ? pv.keep : pv.close);
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

// RFC 9112 3: the head a served file wears. No prebuilt head can hold a
// per-file Content-Length and Last-Modified, so it is spelled byte by byte -
// spell_head's own job, with the run's field lines still in front.
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

// response.file: the reactor is taking the open. The name has to stay put -
// the SQE points straight at these bytes - so nothing clears it until the
// answer is spelled.
const char *Http1::file_take(Conn &conn)
{
    if (conn.file == nullptr || conn.file->stage != FileStage::kNamed)
        return nullptr;
    conn.file->stage = FileStage::kRing;
    return conn.file->pathname.c_str();
}

// One answer for every refusal: a name that was never there, a directory, a
// "..", a symlink out of the docroot, a /proc magic-link. Same status, same
// bytes, same shape - so an attacker cannot tell a caught escape from a
// miss and probe the filesystem through the difference.
void Http1::file_reject(Conn &conn)
{
    file_prebuilt(conn, 404);
}

// RFC 9110 6.4: what the ring answered for one spill write. The octets
// are in the file now, or the write failed and the body can never be
// read.
//
// The body being whole on the wire is not the same as the body being
// whole in its file, and a run reads the file. So this is where a run
// that stopped for its body learns that it may go on.
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
    // The body is whole on the wire and whole in the file now, so the run
    // that stopped for it may walk on.
    if (sp == &conn.spill && sp->ended && sp->drained() && conn.run_wants_body) {
        Conn::Round *const round =
            conn.park_at(conn.parked.co ? conn.parked.co.promise().park : -1);
        if (round != nullptr)
            round->answer_ready = true;
    }
    if (mrb_unlikely(sp->failed)) {
        // The file cannot hold this body, so the request cannot be
        // answered from it. h1 ends the connection; an h2 stream ends on
        // its own below, through the round the reactor spells.
        if (sp == &conn.spill) {
            conn.body_to = Conn::Body::kNone;
            conn.content_need = 0;
            conn.run_wants_body = false;
        }
        return;
    }
}

// The server's own fault: named in the error log, never in the answer.
void Http1::file_error(Conn &conn, const char *why)
{
    log_internal_error(elog_, {{static_cast<const char *>(conn.peer), conn.peer_len},
                               conn.file->request_target,
                               why,
                               500});
    // Once a window has gone out the answer is committed: the head named a
    // Content-Length this body can no longer reach, so a 500 spelled here
    // would land behind those bytes and the client would wait forever for the
    // rest. RFC 9112 6.3: the only way left to say "this is not the whole
    // representation" is to close the connection under it.
    if (conn.file->content_sent != 0) {
        conn.file->content_length = conn.file->content_sent;
        conn.file->buf_filled = 0;
        conn.file->persist = false;
        conn.file->stage = FileStage::kDeliver;
        return;
    }
    file_prebuilt(conn, 500);
}

// statx on the opened fd. Only a regular file within the ceiling earns a
// read; everything else is answered here and the fd goes straight back.
// True = the bytes are still owed.
bool Http1::file_stat(Conn &conn, const struct statx &file_stat, size_t *want)
{
    if (!S_ISREG(file_stat.stx_mode)) {
        // A directory, a fifo, a device: not a representation, and saying which
        // would be the distinguishable answer this whole path avoids.
        file_reject(conn);
        return false;
    }
    const size_t length = static_cast<size_t>(file_stat.stx_size);

    // RFC 9110 8.8.2: Last-Modified, whole seconds, in front of whatever field
    // lines the run itself spelled.
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
        // The head still states the real length; HEAD just sends no bytes.
        file_spell(conn, {200, length, false});
        return false;
    }
    file_spell(conn, {200, length, false});
    conn.file->stage = FileStage::kRing; // the head stands, the bytes are owed
    conn.file->content_length = length;
    conn.file->content_sent = 0;
    // [tune] file_map_threshold: 0 is "never map", so it is not a plain >=.
    conn.file->map_wanted = map_min_ != 0 && length >= map_min_;
    // One meaning: what one read may take. How long the mapping is has its
    // own answer, in file_map_len.
    *want = length < kResponseFileWindow ? length : kResponseFileWindow;
    return true;
}

// Where the ring reads the bytes. Only ever called with no read in flight.
char *Http1::file_buffer(Conn &conn, size_t length)
{
    if (conn.file->buf.size() < length)
        conn.file->buf.resize(length);
    return &conn.file->buf[0];
}

// The whole file, mapped. No read happened and none will: the next round lends the
// mapping to one send and zc_release() gives it back when that round drains.
void Http1::file_mapped(Conn &conn, const char *bytes, size_t length)
{
    // A mapping still installed here belongs to no round: nothing lent it,
    // so nothing will hand it back.
    conn.map_release();
    conn.file->map_addr = bytes;
    conn.file->map_length = length;
    conn.file->buf_filled = length;
    conn.file->content_length = length;
    conn.file->content_sent = 0;
    conn.file->stage = FileStage::kDeliver;
}

// The one place a transfer's state changes as a round goes out. Everything
// it does was decided by file_step over a snapshot; nothing is decided here.
void Http1::file_apply(Conn &conn, const FileStep &step)
{
    if (conn.file == nullptr)
        return;
    conn.file->content_sent = step.sent_after;
    conn.file->stage = step.next;
    if (step.head)
        conn.file->head.clear(); // the head rides the first round
    if (step.log)
        file_log(conn); // before file_clear takes the strings
    if (step.release_map)
        conn.map_release();
    if (step.clear)
        conn.file_clear();
}

// RFC 9110: one access line per request, with the bytes that really left.
// A transfer that ends in sixteen windows is one request, not sixteen.
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

// A connection dying under a transfer still owes its line - that event is
// exactly what an operator wants to see. The stage is the guard: a transfer
// that reached kNone has already written its line and cannot write a second.
void Http1::file_abandon(Conn &conn)
{
    if (conn.file == nullptr || conn.file->stage == FileStage::kNone)
        return;
    file_log(conn);
    conn.file->stage = FileStage::kNone;
}

// The bytes are in. `spell_next_round` is what puts head and body on the wire.
void Http1::file_ready_now(Conn &conn, size_t length)
{
    conn.file->buf_filled = length;
    conn.file->stage = FileStage::kDeliver;
}

// RFC 9112: the framer. phr on the wire bytes, the carry only when a head
// splits; RFC 9113 3.4 decides h2 on the first bytes; the flow decides
// every status.
// #80: Held's out-of-line half. It is out of line because phr_header is
// incomplete in webmachine.hpp on purpose - the framer's header does not
// belong in this tree's one contract - and a unique_ptr<T[]> needs T
// complete exactly where these are defined.
Http1::Held::Held() = default;
Http1::Held::~Held() = default;
Http1::Held::Held(Held &&) noexcept = default;
Http1::Held &Http1::Held::operator=(Held &&) noexcept = default;

void Http1::Held::hold(const char *head_at, size_t head_len, const ReqView &from,
                       const std::string *target)
{
    // The same head, held twice. A run that stops a second time already
    // reads this copy: copying it onto itself would read the buffer the
    // kernel has back, and free the fields array it is reading from.
    if (!head.empty() && head_at == head.data())
        return;
    head.assign(head_at, head_len);
    const ptrdiff_t delta = head.data() - head_at;
    // The two runs of bytes a view can point into, and one mover for them.
    // A pointer in neither is left where it is - hold owns what it copied
    // and nothing else.
    const Span head_span{head_at, head_len, delta};
    Span target_span{};
    if (target != nullptr && from.request_target != nullptr) {
        target_span = {from.request_target, from.request_target_len,
                       target->data() - from.request_target};
    }
    const auto move = [&](const char *&bytes) {
        if (!head_span.move(bytes))
            target_span.move(bytes);
    };

    vals = *from.values;
    http::rebase(vals, delta);

    nfields = from.field_count;
    if (nfields != 0) {
        fields = std::make_unique<struct phr_header[]>(nfields);
        const auto *src = static_cast<const struct phr_header *>(from.fields);
        for (size_t i = 0; i < nfields; i++) {
            fields[i] = src[i];
            if (fields[i].name != nullptr)
                fields[i].name += delta;
            if (fields[i].value != nullptr)
                fields[i].value += delta;
        }
    }
    vals.named = from.values->named;

    // RouteSpans: only the ones nbind/has_splat say are readable. Past
    // nbind the array is uninitialised by contract, and moving those would
    // be reading it.
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
    // The body too: it lies in the same buffer as the head, and the run
    // reads request.body after it resumes. A body in a file needs none of
    // this - rv = from carried its descriptor, and the file outlives every
    // buffer the kernel takes back.
    if (from.content != nullptr && from.content_len != 0) {
        content.assign(from.content, from.content_len);
        rv.content = content.data();
    } else {
        rv.content = from.content;
    }
    rv.content_len = from.content_len;

    // The check the member table cannot do for itself. kReqValueSpans is a
    // list, and a list can be short by one - and the member it is short by
    // is a pointer still aimed at a buffer the kernel already has back. So
    // look at ReqValues as words and refuse any that still lands in the
    // source: a forgotten member is found here, on the first parked run in
    // a debug build, instead of in production on the rarest path there is.
    //
    // The epoch fields are words too and are read the same way. A date in
    // seconds cannot collide with a stack or heap address, so they cost
    // nothing but the loop.
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

// #80: the bound answer, out of feed_parse's loop body. It is a function
// because a run that parks has to return out of it and re-enter later,
// and an inline block inside a loop body cannot be re-entered. What the
// loop held is in the Round and the BoundAsk beside it.

// #80: what happens to a bound run's answer after the walk - the lend,
// the error asset, response.file, and the head a run spells for itself.
// It is its own function because two callers reach it: the straight one
// above, and the coroutine that a promising resource is run through.
// Both arrive here with the same three facts, and out carries them in.

// #80: what the walk is handed, built once. Both entries need it - the
// straight one, and the coroutine a promising resource runs through -
// and neither may build it differently from the other.
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
    // RFC 9110 6.4: the view carries a body only where a node of this
    // resource can read one. A resource without those callbacks never
    // waited for the body, so what sits behind the head is a part of it -
    // and request.body must answer nothing rather than that part.
    // RFC 9112 7.1: a chunked body declares nothing, so what it holds is
    // what has arrived. The count is the length the flow is told about.
    const bool chunked = conn.body_to == Conn::Body::kChunkMem ||
                         conn.body_to == Conn::Body::kChunkFile || conn.body_count != 0;
    result.declared_len = chunked ? conn.body_count : round.content_length;
    if ((round.content_length != 0 || chunked) && block->res->takes_body) {
        // #36: is the whole body here? The walk reads this at kN11, kO14
        // and kP3 and stops there while octets are still coming. Every node
        // above them decided on the head alone.
        //
        // Whole on the wire is not whole in the file. A body that arrived
        // with its head owes no octets, but its spill write may still be in
        // the queue or in flight, and a run handed the descriptor now reads
        // an empty file - and request.body.save links that empty file. So
        // a file body is ready only once the last write landed, and
        // spill_wrote is what makes the round ready when it does.
        const bool on_wire = chunked ? conn.body_to == Conn::Body::kNone : conn.content_need == 0;
        result.content_ready = on_wire && (conn.spill.fd < 0 || conn.spill.drained());
        if (!result.content_ready) {
            // Nothing is bound while octets are still coming. The walk stops
            // at the first node that reads content, and the resume binds the
            // whole body - a part of one is never handed to a callback.
        } else if (conn.spill.fd >= 0) {
            // RFC 9110 6.4: this body is a file. request.body reads it from
            // offset 0, and spill_written is how far the octets go.
            result.content_fd = conn.spill.fd;
            result.content_len = conn.spill.written;
            conn.spill.bound = true;
        } else if (chunked) {
            // The reader wrote it into the hold, chunk by chunk, and the
            // framing octets are not in it.
            result.content = conn.body_hold.empty() ? nullptr : conn.body_hold.data();
            result.content_len = conn.body_hold.size();
        } else {
            result.content = view + offset + head_len;
            result.content_len = round.content_length;
        }
    }
    prep.accept_gzip = !facts.has_accept_encoding ||
                       http::gzip_acceptable(vals.accept_encoding, vals.accept_encoding_len);
    // A run may lend its body only where nothing downstream touches the
    // bytes anyway: HEAD sends none, gzip copies them, one connection
    // holds one lend, and an external segment fits through a plan only.
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
    // #210 response.error_asset: the run named an entry of the error
    // assets, and an entry goes on the wire the way the asset tier
    // already puts one there - through Assets' own accessors, which
    // are the one place that knows an entry's wire form. It lives in
    // a mapping that outlives every request, so nothing here is
    // rooted and nothing is released: a plan carries the segment
    // (wire_iov), and without one the bytes are copied (copy_wire).
    if (mrb_unlikely(block->res->run.asset != nullptr)) {
        const AssetEntry &asset_entry = *block->res->run.asset;
        const size_t length = Assets::wire_len(asset_entry);
        if (plan != nullptr) {
            struct iovec iov[3];
            const unsigned k = Assets::entry_wire_iov(asset_entry, {0, length}, iov);
            // One segment for a stored entry; a deflated one would be
            // three, and response.error_asset refuses those - the head
            // spelled here carries no Content-Encoding to declare them.
            lent = k == 1 ? static_cast<const char *>(iov[0].iov_base) : nullptr;
            lent_len = k == 1 ? iov[0].iov_len : 0;
        }
        if (lent == nullptr) {
            request_ask.body.clear();
            Assets::entry_copy_wire(asset_entry, {0, length}, request_ask.body);
        }
    }
    // response.file: the run named a file instead of spelling a body,
    // and opening one is disk work that does not belong in a reactor
    // step. Nothing is answered here - the framing this answer will need
    // is copied onto the connection, the reactor drives openat2/statx/
    // read through the ring, and `spell_next_round` puts the result on the wire. A
    // name this process already refused takes the same 404 the kernel's
    // own refusal takes, spelled right here since no ring trip is owed.
    {
        if (mrb_unlikely(answer_from_file(round, status, request_ask.rhdrs))) {
            request_ask.body.clear();
            // accept_gzip came in with `out` and stays there: the caller read
            // Accept-Encoding once, and a file answer does not change what the
            // client will take.
            out_answer.status = status;
            out_answer.have_body = false;
            out_answer.answered = false;
            out_answer.lent = nullptr;
            out_answer.lent_len = 0;
            return Took::kOwed;
        }
    }
    // RFC 9110 6.3: field lines or a conneg no prebuilt head can hold -
    // this run spells its own. 500 stays on the exception path below.
    if (mrb_unlikely((!block->res->run.content_type.empty() || !request_ask.rhdrs.empty()) &&
                     status != 500)) {
        const bool bodyless = status == 204 || status == 304;
        if (bodyless || !have_body) {
            request_ask.body.clear();
            conn.zc_release();
            lent = nullptr;
            lent_len = 0;
        }
        // helpers.rb encode_body: a `def self.to_html` renders at setup, so
        // a run that reaches o18 with one produces no body - the bundle's
        // prebuilt 200 carries it. That head is not the one being spelled
        // here, so the bake has to be named, or this answer goes out empty.
        const bool baked = !bodyless && !have_body && lent == nullptr && status == 200 &&
                           !block->dynamic_body && !block->konst.body.empty();
        std::string ctype;
        std::string epage;
        // RFC 9110 15: a 4xx or 5xx is owed the page its status carries,
        // and a run that wrote a field of its own - a 405's Allow, most
        // often - lands here instead of at spell_error. Without this it
        // goes out as the bare status: the same answer the prebuilt one
        // gives, minus the page the prebuilt one has.
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

// #80: the bound answer for a resource that declared a compute task, in a
// frame that can stop. The whole reason this is a coroutine and not a
// stage on the connection: at the stop, `view`, `method`, `path` and
// every span in ReqValues point into a provided buffer, and on_recv
// hands that buffer back to the kernel before anything could resume.
// The bytes have to be copied either way; a frame the compiler manages
// is the copy that cannot be short by one member.
//
// A resource that never says `compute` never reaches this. Its answer
// goes through answer_bound, straight, with no frame.
// The compute round, out of line and out of feed_parse: everything here
// happens only for a resource that said `compute`, and feed_parse is
// walked by every request that did not.
Http1::ComputeRound Http1::start_compute_round(Conn &conn, const BoundStart &text,
                                               std::string *sink, Plan *plan, size_t &offset)
{
    conn.parked = run_parkable(conn, {RunStart::Proto::kH1, text}, sink, plan);
    // The bookkeeping is done here either way, because the bytes it moves
    // belong to the buffer the parse was handed, and a stopped run
    // outlives it. BoundStart::off is already past the head, which is
    // what the parse has to carry on from.
    offset = text.off;
    // #36: a run that waits for the body is not stepping over it - the
    // octets are in the connection's hold and the run reads them when the
    // last one lands. BoundStart::off is already past what arrived.
    if (text.content_length != 0 && !conn.run_wants_body) {
        const size_t avail = text.viewlen - offset;
        const size_t skip = text.content_length < avail ? text.content_length : avail;
        offset += skip;
        conn.content_skip = text.content_length - skip;
    }
    if (!conn.parked.done()) {
        // Stopped. What is left in the buffer waits in the carry: RFC 9112
        // 9.3.2 puts the answers out in the order the requests came, so
        // nothing behind it may speak first.
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
    // h2 asks for its own bundle after the walk; h1 was handed one.
    const Bundle *const block = h1 ? text.b : nullptr;

    // The frame's own scratch. A parked run may share none of it with the
    // next request on this connection: that one would write over what this
    // one still owes.
    std::string body;
    std::string rhdrs;
    Held held;
    bool have_body = false;
    // #53: an h2 body the resume binds. The octets live on the stream, and
    // the stream table is a vector that a new HEADERS frame may move, so a
    // run that stops again after reading its body would be left pointing
    // into the old allocation. The frame takes them instead: it outlives
    // every stop this run can make. h1 needs none of this - its body is
    // the connection's, and the connection serves one request at a time.
    std::string h2_content;

    // RFC 9112 9.3: the request decided this, and the caller reads it off
    // the frame - whether that caller is the parse that started the run or
    // the round that resumed it.
    Run::promise_type &me = co_await Self{};
    me.persist = h1 ? text.persist : true;

    {
        BoundPrep prep;
        H2Produced hpack;
        // h2 answers from copies: the dispatch buffers die with the round
        // that read them, and a parked run answers after that. No Values
        // either - the bytes went with them.
        // Did this run stop? A stopped one logs its own answer from the
        // tail, because the caller logged nothing for it.
        bool stopped = false;
        // #54: a run that can stop reads its request from its own frame.
        // The dispatch's decode buffer is gone by the time a stopped run
        // answers, so the head is copied here - the same hold h1 does, and
        // for the same reason.
        //
        // Before this, a parked h2 run was given no view and no values at
        // all: a resource that stopped could not read a header, a path
        // binding or its own body.
        const bool h2_held = !h1 && start.h2.view != nullptr && start.h2.head_at != nullptr;
        // #54: the target is the run's own copy. A parked stream's view
        // points at a target beside its fields, not inside them, so the
        // target says where those pointers go and the head says where the
        // fields go.
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

            // can_park: this frame is the thing that can hold a stopped run, so
            // the walk may stop in it. What answers the stop is a worker, and
            // the crossing to one is complete.
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
        // Which resource ran, if one did. A konst h2 route runs none, and
        // then nothing here can stop.
        const Bundle *const rb = h1 ? block : hpack.b;
        const Resource *const ran = (rb != nullptr && rb->bound) ? rb->res : nullptr;

        // #30: what this run waits on, in the frame that holds the run. The
        // connection only learns its address, under a park slot, because a
        // completion carries a number and not a pointer.
        Conn::Round mine_round;
        int park = -1;
        while (mrb_unlikely(ran != nullptr && run_stopped(*ran))) {
            const Resource &resource = *ran;
            // The head, copied, and everything re-pointed at the copy. After
            // this the provided buffer may go back to the kernel.
            //
            // #30: h1 only. An h2 run started from copies - RunStart::H2Start
            // carries the facts and the target - because the dispatch buffers
            // die with the round that read them.
            if (h1) {
                held.hold(text.head_at, text.head_len, prep.rv, nullptr);
                // The head this run reads from here on. A second stop holds the
                // copy rather than the buffer the kernel has back.
                text.head_at = held.head.data();
                // The view the run bound (res.run.req is &prep.rv) reads the copy
                // from here on, not the buffer the kernel has back.
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

            // The crossing, before the state travels: the block becomes an id
            // and the arguments become CBOR while both the VM and the run's
            // own state are still to hand. One line later res.run is gone
            // from the resource, and neither could be read again.
            if (park < 0) {
                park = conn.park_take(&mine_round);
                me.park = park;
            }
            // #36: a run waiting for the body owes nothing to a worker and
            // nothing to the ring. The connection is already taking the
            // octets, and the last one makes this round ready - so there is
            // no crossing to make and no descriptor to arm.
            if (mrb_unlikely(resource.run.wants_body)) {
                mine_round.wants_body = true;
                mine_round.jobs_owed = 0;
            } else {
                compute_task_hand_over(conn, mine_round, park, resource);
                // #30: the same moment for a watcher. It is a value of the
                // reactor's VM and it must reach the connection's hash before the
                // frame takes res.run away - a watcher nobody roots is collected
                // while its descriptor is still in the ring. A connection that can
                // hold no more says so, and the run is answered rather than left
                // waiting for a poll nobody armed.
                if (resource.run.watch_count != 0 &&
                    !watch_hand_over(conn, mine_round, park, resource)) {
                    mine_round.answer_value.at(0) = mrb_nil_value();
                    mine_round.jobs_owed = 0;
                    mine_round.answer_ready = true;
                }
            }

            // The walk's own state travels with the frame. res.run belongs to
            // the route, and the next request on it would write over this.
            //
            // #30: this frame holds everything about the run it left, and a
            // watcher block of that run needs it back for as long as it
            // speaks. So each watcher is told where it is - a pointer into
            // this frame, which outlives every wait it started, and one per
            // run rather than one per connection.
            Resource::RunState mine = std::move(resource.run);
            resource.run = Resource::RunState{};
            watch_run_is(conn, mine_round, &mine);
            // #80: if this frame is destroyed while the run waits - the peer
            // left, Conn::reset ran - the roots run_settle took and the
            // answers the round already holds are given back here. On the
            // way back the guard is disarmed: res.run owns them again.
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
                    for (int i = 0; i < Conn::kJobSlots; i++) {
                        if (round->user_have.at(i))
                            mrb_gc_unregister(resource->mrb, round->user_value.at(i));
                        round->user_have.at(i) = false;
                    }
                }
            } parked_roots{&resource, &mine, &mine_round};

            Run::promise_type &pr = co_await Park{};
            parked_roots.resource = nullptr;
            stopped = true;

            // Back, into a round that is not the one that left. Only the wire
            // is the resumer's: the sink to write into and the plan a lend
            // rides out on, because the ones this run started with were
            // locals of a parse that has returned.
            //
            // RFC 9112 9.3: `persist` is not the resumer's. Whether the
            // connection lives past this answer was decided by the request
            // itself - its version and its Connection field - before the run
            // began. It travels in this frame, and `spell_next_round` reads it back out of
            // the promise_type once the run is done.
            sink = pr.sink;
            plan = pr.plan;
            pr.persist = text.persist;
            // What the resource holds now is another request's leftovers, and
            // its userdata root would be lost under the move.
            resource_forget_userdata(resource);
            resource.run = std::move(mine);
            // Back in the resource. Nothing may point at this frame's copy
            // any more - a watcher that outlived its answer would lend a
            // state that has moved.
            watch_run_is(conn, mine_round, nullptr);
            // Three refusals, and they must not be confused: a full pool is
            // load and passes, a deadline the author got wrong does not, and
            // a handle that died may come back.
            // A refused run does not walk on - there is no answer to walk to.
            const ComputeRefusal refused = compute_task_refusal(mine_round);
            if (mrb_unlikely(refused.status != 0)) {
                // Nothing the run said still holds: it never reached an answer.
                // A content type, a file name, an error asset - all of them
                // belong to a walk that was refused, and the finish would try
                // to serve them. The status and the Retry-After are the whole
                // answer. The roots the wait took are given back with it.
                resource_abandon(resource, resource.run);
                status = refused.status;
                have_body = false;
                body.clear();
                rhdrs.assign(refused.retry_after);
            } else if (mrb_unlikely(mine_round.wants_body)) {
                // #36: the body is whole. Nothing answered for this run - it
                // waited on octets, not on a worker - so the round carries no
                // job and the walk runs the node itself, with the content in
                // reach. `content_seen` is already set, so it does not stop on
                // that node a second time.
                //
                // res.run.req points at the view this frame holds - prep.rv for
                // h1, held.rv for h2 - and the hold re-pointed it at the copied
                // head. So the body binds here, in the frame that outlives the
                // parse.
                //
                // #53: where the body is depends on the protocol. h1 keeps one
                // per connection, because it answers one request at a time. h2
                // keeps one per stream, because it does not.
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
                    // The stream may be gone: a RST_STREAM closes the entry while
                    // the run is parked. Then there is no body to bind and the
                    // walk reads none - the run answers from the head it holds.
                    H2Stream *const owner =
                        conn.h2 != nullptr ? conn.h2->find(start.h2.stream_id) : nullptr;
                    if (owner != nullptr) {
                        if (owner->spill.fd >= 0) {
                            // The file is the stream's until close_stream drops the
                            // entry, so the descriptor is still this run's to read.
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
                                         {mine_round.answer_value, mine_round.job_what,
                                          mine_round.user_value, mine_round.user_have, 0});
            } else {
                // #30: the whole round, in the order the stop handed it over.
                // A watcher and a single task are one entry of it.
                const uint8_t owed = mine_round.jobs_owed != 0 ? mine_round.jobs_owed : 1;
                status = resource_resume(resource, {&body, &have_body, &rhdrs},
                                         {mine_round.answer_value, mine_round.job_what,
                                          mine_round.user_value, mine_round.user_have, owed});
            }
            // The answers were rooted while they waited - nothing on the VM's
            // stack named them. The round is read, so they are let go.
            for (mrb_value &a : mine_round.answer_value) {
                if (!mrb_nil_p(a)) {
                    mrb_gc_unregister(resource.mrb, a);
                    a = mrb_nil_value();
                }
            }
            for (int i = 0; i < Conn::kJobSlots; i++) {
                if (!mine_round.user_have.at(i))
                    continue;
                mrb_gc_unregister(resource.mrb, mine_round.user_value.at(i));
                mine_round.user_value.at(i) = mrb_nil_value();
                mine_round.user_have.at(i) = false;
            }
        }

        // The run is done stopping. The slot goes back, and nothing in the
        // table names this frame any more.
        if (park >= 0) {
            // #30: a watcher this round armed and never heard from. A refused
            // round answers at once, and a hand-over that ran out of slots
            // stops half way - either way what is left points at this frame,
            // and this frame ends on the next line. The connection stops
            // naming it, so the poll that fires later finds an empty slot and
            // answers nobody.
            for (const int slot : mine_round.w_slot) {
                if (slot >= 0)
                    watchers_drop_slot(conn, slot);
            }
            conn.park_drop(park);
            me.park = -1;
        }

        // #30: the h2 tail. The walk is over, so what it left can be read
        // now, and the frames go out through the same framer the straight
        // path uses.
        if (!h1) {
            // What the resumed walk answered is in this frame's locals, not in
            // what the walk said before it stopped.
            hpack.have_body = have_body;
            // RFC 9113 5.1: the peer reset the stream while the run was
            // parked. Its entry is gone, and the answer goes to nobody.
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
            // response.file: the reactor fetches it and spell_next_round puts
            // it on the wire. Nothing is spelled here.
            co_return 0;
        }
        const AnswerStep astep =
            spell_answer(fr, {*sink, plan, out_answer.status, out_answer.lent, out_answer.lent_len,
                              out_answer.answered, out_answer.have_body, out_answer.accept_gzip,
                              &block->index, body});
        // The access line is written here and not by the caller: a stopped
        // run answers long after the caller returned, and the line belongs
        // to the answer, not to the parse that started it.
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
        // RFC 9112 9.3: the caller reads this out of the compute task, whether it
        // is the parse that started the run or the round that resumed it.
        co_return out_answer.status;
    }
}

Http1::Took Http1::answer_bound(Round &round, const BoundAsk &request_ask, BoundOut &out_answer)
{
    // What this function reads. Spelling the answer belongs to
    // bound_finish and spell_answer.
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

// RFC 9113 3.4: the first bytes of a fresh connection decide the
// protocol. The preface is matched across receives; a connection that
// sent enough of it to be h2 and then diverged is refused with GOAWAY.
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

// RFC 6455 4.2 and WHATWG HTML: a head that upgrades to a WebSocket, or
// names an event-stream route, leaves the request path here. Returns
// whether it was taken; `lives` then says whether the connection goes
// on. A head that is neither falls back to the tables.
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
        const int sr = sslot.sse_table->match(headers.path.data(), headers.path.size(), sspans);
        if (sr >= 0) {
            const SseBegin req{sslot,
                               sr,
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

// RFC 9112 2.2 and 5.2: how this server's head framing is stricter than
// the parser that reads it. picohttpparser accepts both of these, so the
// refusal has to be ours, and it is one walk over a head that already
// parsed. 0 = the head is well framed, otherwise the status it earns.
//
// RFC 9112 5.2: obs-fold. The text gives a server two answers and no
// third - reject the message with 400, or replace each fold with SP
// before it reads the field value. This server did neither: the fold was
// dropped, so a folded field went missing with no word to anybody.
// picohttpparser reports a continuation line as a field with no name,
// which is what this counts. 400 is the answer the text prefers.
//
// RFC 9112 2.2: a bare LF. The text permits a recipient to read a single
// LF as a line terminator, so this is a choice and not a defect - and
// the choice is to refuse. A front end that holds out for CRLF reads
// `Dummy: a LF Content-Length: 5` as one field value and sees no body,
// while a server that splits the line sees a body of five octets. The
// two then disagree about where the message ends, which is request
// smuggling (RFC 9112 11.2). llhttp's strict mode and Node refuse it for
// the same reason. Every line of a head that parsed ends with LF, so an
// LF with no CR in front of it is a line this server will not read.
//
// Cold: once per head, and only after the head is whole.
__attribute__((noinline)) static uint16_t
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

// RFC 9110 15: the status a refused body take earns. Cold - once per
// refused body, never per buffer - so it stays out of feed_parse.
__attribute__((noinline)) static uint16_t body_take_status(BodyTake took)
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

bool Http1::feed_parse(Conn &conn, std::string_view in, Sink out_answer)
{
    const char *data = in.data();
    size_t length = in.size();
    std::string &sink = out_answer.bytes;
    Plan *const plan = out_answer.plan;
    if (conn.h2 != nullptr)
        return h2_feed(conn, in, out_answer);
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
    // The state and the pointers must say the same thing, and the parts
    // must stand to one another the way Conn::invariant_broken says. This
    // is the top of the feed on purpose: the paths below return as soon
    // as they have taken their octets, so a check under them would never
    // see a connection with a body in flight. The debug build is what
    // every test in this tree runs, so a drift fails the suite instead of
    // answering a request from a state nobody declared.
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
        const size_t take = conn.content_skip < length ? conn.content_skip : length;
        conn.content_skip -= take;
        data += take;
        length -= take;
        if (length == 0)
            return true;
    }

    // RFC 9110 6.4: the octets of a body a run is waiting for. The run
    // already walked the head and stopped at kN11, kO14 or kP3; these go
    // where the head decided, and the last one makes its round ready.
    // Nothing behind them is parsed until content_need is paid off.
    //
    // One switch, and it is the question this function had to ask anyway:
    // are these octets a body or the head of a request. The two body arms
    // name a writer, and each writer's code holds no test about where the
    // octets go, because the head answered that before they arrived.
    // RFC 9110 8.3: the octets against the claim the head made. The first
    // 512 of them are kept aside - the body itself may be on its way to a
    // file - and the table reads them once. A contradiction is 415 at the
    // first buffer, so a half gigabyte behind a lie never arrives.
    if (mrb_unlikely(!conn.sniff_type.empty() && !conn.sniff_done && length != 0)) {
        const size_t want = sniff::octets_needed();
        if (conn.sniff_head.size() < want) {
            const size_t room = want - conn.sniff_head.size();
            conn.sniff_head.append(data, length < room ? length : room);
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
        // RFC 9112 7.1: the same two writers, behind a reader that has to
        // find the octets first.
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
        // RFC 9112 7.1: a client fault in the framing of the body. The
        // connection ends without an answer, and the body is dropped. A
        // body that already spilled would keep its file open until the
        // next accept into this slot.
        case BodyTake::kFailed:
            drop_body(conn);
            return false;
        // RFC 9110 15.5.14: a chunked body declares nothing, so this is the
        // first place its size can be refused. The client hears 413, and the
        // octets still on the way are the reason the connection ends with it.
        // RFC 9110 15.6.4: no slot for its file is load, and the client
        // hears 503. RFC 9110 15.6.1: a file the server could not make or
        // write is 500. All three end the connection the same way.
        case BodyTake::kTooLarge:
        case BodyTake::kNoSlot:
        case BodyTake::kFileFailed:
            drop_body(conn);
            return connection_fail(conn, body_take_status(took), sink);
        case BodyTake::kMore:
            return true;
        case BodyTake::kWhole:
            // RFC 9110 6.4: whole on the wire is not whole in the file. The
            // run reads the file, so the last write has to land first. The
            // reactor makes the round ready when it does - see spill_wrote.
            if (conn.spill.fd >= 0) {
                conn.spill.ended = true;
                if (!conn.spill.drained())
                    break;
            }
            // #36: the body is whole. The run stopped on it owes nothing to a
            // worker, so this is what answers it: the round is ready, and
            // spell_next_round resumes the walk at the node it stopped on.
            if (mrb_unlikely(conn.run_wants_body)) {
                Conn::Round *const round =
                    conn.park_at(conn.parked.co ? conn.parked.co.promise().park : -1);
                if (round != nullptr)
                    round->answer_ready = true;
                // No return: what came behind the last octet is a pipelined
                // request, and the guard below puts it in the carry. RFC 9112
                // 9.3.2 answers in the order the requests came, so it may not
                // be parsed while this run is still stopped.
            }
            break;
    }

    if (mrb_unlikely(conn.asset != nullptr)) {
        if (mrb_unlikely(conn.carry.size() + length > kMaxHead)) {
            conn.carry.clear();
            conn.content_skip = 0;
            conn.asset = nullptr;
            conn.become(ConnMode::kHead);
            return false;
        }
        conn.carry.append(data, length);
        return true;
    }

    if (mrb_unlikely(conn.ws != nullptr))
        return ws_feed(conn.ws, in, sink);
    if (mrb_unlikely(conn.sse != nullptr))
        return true;

    // RFC 9112 9.3.2: a run that parked, or a file the ring still owes,
    // is the next answer on this connection. A request that arrives
    // behind it in a receive of its own waits in the carry, and the
    // round that spells that answer feeds the carry.
    if (mrb_unlikely(conn.run_parked() ||
                     (conn.file != nullptr && conn.file->stage != FileStage::kNone))) {
        if (mrb_unlikely(conn.carry.size() + length > kMaxHead))
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
        // RFC 9110 6.4: the body file of the request that just finished goes
        // back here. This connection answers one request at a time - a run
        // that parks stops this loop until it is resumed - so a new head at
        // the top of the loop says the last body has been read for the last
        // time.
        //
        // Only a file a round already took: an unbound one is this request's
        // body still arriving, and the loop runs again for it once the last
        // octet lands.
        if (mrb_unlikely(conn.spill.bound || conn.run_wants_body))
            conn.spill.close_file();
        // #36: the run before this one asked for a body and answered without
        // it - a 401, a 403, a 404 or a 405 stands above the three nodes that
        // read content. Its file, its hold and its flag are the connection's
        // until something ends them, and a head parsed here is what says the
        // last request is over. Left standing they reach the next request:
        // body_have would read the old file, bound_prepare would hand those
        // octets over as this request's body, and the flag would make the
        // parse step over bytes that are a request of their own.
        conn.run_wants_body = false;
        conn.body_hold.clear();
        conn.body_count = 0;
        const char *method;
        size_t method_len;
        const char *path;
        size_t path_len;
        int minor;
        struct phr_header headers[kMaxHeaders];
        size_t num_headers = kMaxHeaders;
        const int ret = phr_parse_request(view + offset, viewlen - offset, &method, &method_len,
                                          &path, &path_len, &minor, headers, &num_headers, 0);
        if (mrb_unlikely(ret == -2)) {
            const size_t rest = viewlen - offset;
            if (mrb_unlikely(rest > kMaxHead))
                return connection_fail(conn, 431, sink);
            if (in_place)
                conn.carry.assign(view + offset, rest);
            else
                conn.carry.erase(0, offset);
            return true;
        }
        if (mrb_unlikely(ret <= 0))
            return connection_fail(conn, 400, sink);
        if (mrb_unlikely(static_cast<size_t>(ret) > kMaxHead))
            return connection_fail(conn, 431, sink);
        // RFC 9112 2.2 and 5.2: a fold, or a line this server will not read.
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
        // RFC 9112 6.1: a request that names both framings is a smuggling
        // attempt, and a coding this server cannot read is 501. Chunked
        // alone is read: the octets arrive without a length and the count
        // is what holds them to a limit.
        if (mrb_unlikely(window.have_te)) {
            if (mrb_unlikely(window.have_cl))
                return connection_fail(conn, 400, sink, lflags);
            if (mrb_unlikely(!window.te_chunked))
                return connection_fail(conn, 501, sink, lflags);
        }
        if (mrb_unlikely(minor >= 1 && !window.have_host))
            return connection_fail(conn, 400, sink, lflags);
        bool persist = minor >= 1 ? !window.conn_close : window.conn_keep;
        const bool head_only = facts.method == flow::Method::kHead;
        // RFC 9112 6.6: this connection ends when the request carries
        // content that no node will read. The answer has to say so, and the
        // head is spelled from `persist`, so the decision belongs here -
        // ahead of every tier that can answer.
        //
        // Only a request with content pays for the extra match, and the
        // match is pure: the route table answers the same both times.
        bool body_read = window.content_length == 0 && !window.have_te;
        // The application's number, until the route names a nearer one.
        size_t limit = apps_[conn.listener].max_body;
        // RFC 9112 7.1: what the chunked reader took out of this buffer,
        // framing and all. The cursor steps over it after the answer.
        size_t chunk_used = 0;
        if (mrb_unlikely(!body_read)) {
            // Only a request that carries content pays for this second
            // match, and the route table is pure: it answers the same both
            // times. Measured: out of line it cost 16 bytes more here and
            // another 515 of its own, so it stays where it is read.
            const AppSlot &probe_slot = apps_[conn.listener];
            RouteSpans probe_spans;
            const int probe = probe_slot.table->match(path, path_len, probe_spans);
            if (probe >= 0) {
                const Bundle &pb = bundles_[probe_slot.base + static_cast<size_t>(probe)];
                body_read = pb.bound && pb.res->takes_body;
                // RFC 9110 15.5.14: the nearest limit answers. This route's
                // resource holds one when it said `def self.max_body`, and the
                // application's number answers for every route that did not.
                if (pb.bound && pb.res->max_body >= 0) {
                    limit = static_cast<size_t>(pb.res->max_body);
                }
            }
            if (!body_read)
                persist = false;
        }
        // RFC 9110 15.5.14: a declared length above the limit is 413, and
        // no octet of the body is read. The check waits for the route
        // probe above, because the route is what can name a nearer limit.
        if (mrb_unlikely(window.content_length > limit)) {
            return connection_fail(conn, 413, sink, lflags);
        }
        // A chunked body declares nothing, so the limit has to travel with
        // the connection: the reader holds the count against it, buffer by
        // buffer.
        conn.body_limit = limit;

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

        // #210: the error assets answer under one reserved prefix, always,
        // and without the operator mounting anything - a page that names a
        // picture has to be able to hand it over. Everything else belongs to
        // whoever passed --assets.
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
            // The standalone tier: a docroot answers what the pack does not,
            // and there is no route table behind it to fall through to.
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
        // Read once, used by both the zero-copy eligibility gate below and
        // assemble_dynamic() further down - Accept-Encoding does not change
        // between the two.
        bool accept_gzip = false;
        if (mrb_unlikely(route < 0)) {
            status = 404;
        } else {
            block = &bundles_[slot.base + static_cast<size_t>(route)];
            idx = &block->index;
            if (mrb_likely(block->bound)) {
                const size_t head_len = static_cast<size_t>(ret);
                const size_t body_here = viewlen - offset - head_len;
                // What is already in hand: the octets behind the head, or - once
                // this body went to a file - what reached the file. The second
                // re-parse of a spilled request finds an empty carry behind the
                // head, and the body is complete all the same.
                const size_t body_have = conn.spill.fd >= 0 ? conn.spill.written : body_here;
                // What of this body is in the buffer. RFC 9112 9.3.2 lets the
                // next request follow the last octet of this one, and those
                // octets are not this body's to take. A declared length says
                // where the body ends; a chunked body ends where the reader says
                // it does, and for that this is every octet behind the head.
                const size_t body_octets =
                    window.content_length != 0 && body_here > window.content_length
                        ? window.content_length
                        : body_here;
                // RFC 9110 6.4: only three callbacks read a request body -
                // content_types_accepted, create_path and process_post. A
                // resource that declares none of them has no node that can ask
                // for one, so this connection waits for nothing and keeps
                // nothing: the octets are stepped over below.
                //
                // Before this, every bound route held the whole upload while
                // the flow walked, and a body of kBodySpill or more went to a
                // file first. A route that never reads a body could be made to
                // do both.
                // RFC 9110 8.3: this route asked for the octets of some types to
                // be checked against the claim. The claim is here, at the head;
                // the octets arrive after it. So the type is kept and the check
                // runs on the first buffer, in sniff_body below.
                if (mrb_unlikely(!block->res->sniff_types.empty()) &&
                    vals.content_type != nullptr) {
                    const std::string_view claim{vals.content_type, vals.content_type_len};
                    if (sniff::was_asked_for(block->res->sniff_types, claim)) {
                        conn.sniff_type.assign(claim);
                        conn.sniff_head.clear();
                        conn.sniff_done = false;
                        // The first octets of a body usually arrive in the buffer
                        // that carried the head, and those never pass the feed's
                        // body switch. So the check starts here, on them.
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
                // RFC 9112 7.1: a chunked body has no length to compare, so the
                // reader starts here and the octets behind the head are its
                // first buffer. It begins in memory and moves to a file when
                // the count says so - the head cannot know which it will be.
                if (mrb_unlikely(window.have_te) && mrb_likely(block->res->takes_body)) {
                    conn.chunk = {};
                    // RFC 9112 7.1.2: the decoder reads the trailer section and
                    // drops it. No node of this server reads a trailer field.
                    conn.chunk.consume_trailer = 1;
                    conn.body_count = 0;
                    // RFC 9112 7.1: the framing budget is per body. Conn::reset
                    // zeroes it per connection, and a kept-alive connection
                    // carries many bodies.
                    conn.chunk_framing = 0;
                    // RFC 9112 7.1.1: the strict walk over the framing starts at a
                    // size line, once per body. A kept-alive connection carries
                    // many bodies, and the walk of the last one must not decide
                    // where this one begins.
                    conn.chunk_scan = Conn::ChunkScan::kSize;
                    conn.chunk_need = 0;
                    conn.chunk_after = 0;
                    conn.chunk_line.clear();
                    conn.body_hold.clear();
                    conn.body_to = Conn::Body::kChunkMem;
                    conn.run_wants_body = true;
                    const char *cp = view + offset + head_len;
                    size_t clen = body_here;
                    const BodyTake read_bytes =
                        take_chunked(conn, MemWriter{&conn.body_hold}, cp, clen);
                    chunk_used = body_here - clen;
                    if (mrb_unlikely(read_bytes != BodyTake::kMore &&
                                     read_bytes != BodyTake::kWhole)) {
                        drop_body(conn);
                        return connection_fail(conn, body_take_status(read_bytes), sink, lflags);
                    }
                    // What the reader did not read is a pipelined request, and it
                    // waits behind a run that has not answered yet.
                    conn.run_wants_body = read_bytes != BodyTake::kWhole;
                } else if (window.content_length != 0 && mrb_likely(block->res->takes_body) &&
                           (body_have < window.content_length || block->res->saves_body)) {
                    // save: true takes this branch with the body already whole, so
                    // the subtraction needs the body's own count. Taking the
                    // buffer's wrapped it to near SIZE_MAX: the file then swallowed
                    // the pipelined request behind the body and every octet the
                    // client sent after it, with max_body seeing only the length
                    // the head declared.
                    const size_t have =
                        body_have < window.content_length ? body_have : window.content_length;
                    conn.content_need = window.content_length - have;
                    // RFC 9110 6.4: a large body goes to a file, so the connection
                    // holds the head and not the upload. The length is declared -
                    // this server refuses a chunked request body - so the choice
                    // is made once, here, and never part way through.
                    // #54: a callback that declared `save: true` gets its body in
                    // a file whatever the size, so request.body.save is a link and
                    // never a second write of the octets. The resource said so
                    // before the first one arrived, which is the only moment this
                    // can be decided.
                    if (window.content_length >= kBodySpill || block->res->saves_body) {
                        // RFC 9110 15.6.4: no slot for the file is load, 503. RFC 9110
                        // 15.6.1: no file is 500. Both end the connection, and the body
                        // still on the way ends with it.
                        const SpillOpen opened = conn.spill.open_file();
                        if (mrb_unlikely(opened != SpillOpen::kOpen)) {
                            return connection_fail(conn, opened == SpillOpen::kNoSlot ? 503 : 500,
                                                   sink, lflags);
                        }
                        if (mrb_unlikely(!conn.spill.take(view + offset + head_len, body_octets))) {
                            conn.spill.close_file();
                            return connection_fail(conn, 500, sink, lflags);
                        }
                        // A body that arrived whole with its head owes no more
                        // octets, and a destination is named exactly while octets
                        // are owed. What it still owes is the write: the run reads
                        // the descriptor, so it waits for the last one to land, and
                        // spill_wrote is what says it did.
                        if (conn.content_need != 0)
                            conn.body_to = Conn::Body::kFile;
                        else
                            conn.spill.ended = true;
                    } else {
                        // #36: a body under kBodySpill waits in body_hold. It cannot
                        // stay behind the head in the carry: the run is about to
                        // read that head, and the carry is where a pipelined
                        // request waits.
                        //
                        // The declared length is the whole size, so the buffer is
                        // taken once and never grows again.
                        conn.body_hold.reserve(window.content_length);
                        conn.body_hold.assign(view + offset + head_len, body_octets);
                        conn.body_to = Conn::Body::kMem;
                    }
                    // #36: the walk starts now, on the head. It stops at kN11,
                    // kO14 or kP3 - the three nodes that read content - and the
                    // last octet of the body makes its round ready again.
                    //
                    // Before this the head waited in the carry until the whole
                    // body had arrived, so is_authorized? and forbidden? were
                    // asked after the upload rather than before it.
                    conn.run_wants_body = true;
                }
                // #80: a resource that declared a compute task is answered inside a
                // frame that can stop. The frame spells the whole answer,
                // including the access line, so nothing below is owed for it.
                // Measured, not chosen: giving this frame to every bound resource
                // breaks response.file - thirteen bintests, all of them a file
                // the run owes and the frame finishes differently. So the gate
                // stays what a resource declared, and a watcher needs a
                // declaration of its own before it can reach this path.
                // #30: a value round stops the run as much as a node does, and
                // a resource may declare only values.
                // #36: a run that waits for the body stops as much as a compute
                // task does, so it needs the same frame. Its BoundStart::off is
                // past the octets that already arrived - they are in the hold,
                // and nothing steps over them.
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
                BoundOut bo;
                // body_ and rhdrs_ are this writer's own scratch, reused request
                // after request. The straight path hands them in; a parked run
                // will hand in a pair of its own.
                const BoundAsk basked = {headers, num_headers, spans, slot.table, route,
                                         plan,    sink,        body_, rhdrs_};
                if (mrb_unlikely(answer_bound(br, basked, bo) == Took::kOwed)) {
                    have_body = false;
                    return true;
                }
                status = bo.status;
                have_body = bo.have_body;
                answered = bo.answered;
                lent = bo.lent;
                lent_len = bo.lent_len;
                accept_gzip = bo.accept_gzip;
            } else {
                // RFC 9110 12.5.1: c4 belongs to the client. The fold left this
                // resource with exactly one media type (two would have bound it), so
                // the question is one match, asked here in C++ and never in the VM.
                if (mrb_unlikely(facts.has_accept && vals.accept != nullptr)) {
                    if (http::accept_is_exact({vals.accept, vals.accept_len}, block->accept_type)) {
                        // Asked and answered: this Accept names the one type offered,
                        // so c3/c4 have nothing left to decide and the request is as
                        // plain as one that never negotiated.
                        facts.has_accept = false;
                    } else {
                        facts.plain = false;
                        facts.accept_ok =
                            http::choose_media_type(
                                {{&block->accept_type, 1}, {vals.accept, vals.accept_len}}) >= 0;
                    }
                }
                const size_t mi = static_cast<size_t>(facts.method);
                status =
                    flow::answer(facts, {block->konst.per_method[mi], block->konst.shortcut[mi]});
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
        // RFC 9112 6.6: this request carried content and no node of the flow
        // asked for it. A route that does not exist, a method that is not
        // allowed, a resource that declares none of the three callbacks that
        // read a body - each answers before any node wants content.
        //
        // The answer is already in the sink and goes out. The connection
        // ends behind it, because reading the rest to stay alive would read
        // exactly what the flow refused. RFC 9110 9.3.1 names the risk:
        // content behind a request nobody parsed is where request smuggling
        // lives. A GET carries none of it - RFC 10008 QUERY is the method
        // for a safe request that needs content.
        if (mrb_unlikely(!body_read)) {
            conn.carry.clear();
            conn.content_skip = 0;
            conn.content_need = 0;
            return false;
        }
        // RFC 9110 6.4: step over the body this round did not read. A body
        // that went to a file is already off the wire and out of the buffer,
        // so there is nothing here to step over - counting it again would
        // make the next request's head look like this request's body.
        if (window.content_length != 0 && conn.spill.fd < 0) {
            const size_t avail = viewlen - offset;
            const size_t skip = window.content_length < avail ? window.content_length : avail;
            offset += skip;
            conn.content_skip = window.content_length - skip;
        }
        // RFC 9112 7.1: the chunked reader took its own octets out of this
        // buffer, framing and all, so the cursor steps over exactly what it
        // read and the next head starts where the body ended.
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

// RFC 6455 4.2.2: the handshake's answer, 101 or the refusal the route earned.
bool Http1::ws_upgrade(Conn &conn, const WsUpgrade &up, std::string &sink)
{
    const AppSlot &slot = up.slot;
    const int route = up.route;
    const std::string_view path = up.path;
    const RouteSpans &spans = up.spans;
    const void *hdrs = up.hdrs;
    const size_t nhdr = up.nhdr;
    const http::ReqValues &vals = up.vals;
    char accept[28];
    if (!ws::accept_key_compute(up.key.data(), up.key.size(), accept))
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
    conn.ws = wsc;
    conn.become(ConnMode::kWs);
    conn.carry.clear();
    conn.content_skip = 0;
    if (!up.rest.empty())
        return ws_feed(conn.ws, up.rest, sink);
    return true;
}

// One line of the access log for an event stream that got an answer.
void Http1::log_sse(Logger &lg, const Conn &conn, const SseLine &line)
{
    if (!lg.enabled)
        return;
    const std::string_view method = line.method;
    const std::string_view path = line.path;
    const http::ReqValues &vals = line.vals;
    const uint8_t lflags = line.lflags;
    const uint16_t status = line.status;
    log_access(lg, {{static_cast<const char *>(conn.peer), conn.peer_len},
                    method,
                    path,
                    {vals.log_ref, vals.log_ref_len},
                    {vals.log_ua, vals.log_ua_len},
                    0,
                    status,
                    lflags});
}

// WHATWG HTML: the event stream's head - RFC 9112 7.1 chunked, RFC 9111
// 5.2.2.5 no-store, and this connection never reads another head.
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
        // RFC 9110 15.5.4: a stream the app would not open is a 403 unless the
        // app named a status of its own.
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
