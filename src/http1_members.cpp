// The bodies of the members http1.hpp declares.
#include "http1.hpp"

namespace webmachine
{
__attribute__((noinline)) void BodySpill::close_file()
{
    if (fd < 0)
        return;
    ::close(fd);
    body_file_slot_give();
    fd = -1;
    written = 0;
    bound = false;
    pending.clear();
    in_flight = false;
    offset = 0;
    failed = false;
    ended = false;
}

__attribute__((noinline)) SpillOpen BodySpill::open_file()
{
    close_file();
    if (mrb_unlikely(!body_file_slot_take()))
        return SpillOpen::kNoSlot;
    fd = slipstream_tmpfile(spill_dir_get());
    if (mrb_unlikely(fd < 0)) {
        fd = -1;
        body_file_slot_give();
        return SpillOpen::kNoFile;
    }
    return SpillOpen::kOpen;
}

BodySpill::~BodySpill()
{
    close_file();
}

BodySpill::BodySpill(BodySpill &&other) noexcept
    : fd(other.fd), written(other.written), bound(other.bound), pending(std::move(other.pending)),
      in_flight(other.in_flight), offset(other.offset), failed(other.failed), ended(other.ended)
{
    other.fd = -1;
    other.written = 0;
    other.bound = false;
    other.in_flight = false;
    other.offset = 0;
    other.failed = false;
    other.ended = false;
}

bool BodySpill::take(const char *bytes, size_t count)
{
    if (mrb_unlikely(failed))
        return false;
    pending.append(bytes, count);
    return true;
}

bool BodySpill::owes_write() const
{
    return fd >= 0 && !failed && !in_flight && !pending.empty();
}

bool BodySpill::drained() const
{
    return !in_flight && pending.empty();
}

void BodySpill::fly_into(std::string &out_value)
{
    out_value.swap(pending);
    pending.clear();
    in_flight = true;
}

void BodySpill::wrote(ssize_t resource, const std::string &out_value)
{
    in_flight = false;
    if (mrb_unlikely(resource <= 0)) {
        failed = true;
        pending.clear();
        return;
    }
    const size_t count = static_cast<size_t>(resource);
    offset += count;
    written += count;
    if (count < out_value.size())
        pending.insert(0, out_value, count, out_value.size() - count);
}

bool MemWriter::put(const char *bytes, size_t count) const
{
    mem->append(bytes, count);
    return true;
}

bool FileWriter::put(const char *bytes, size_t count) const
{
    return spill->take(bytes, count);
}

H2State::H2State()
{
    hpack_ready = lshpack_enc_init(&enc) == 0;
    lshpack_dec_init(&dec);
    lshpack_dec_set_max_capacity(&dec, kH2DecTableSize);
    // The dynamic table needs nothing done to it here any more. This
    // used to hand the decoder an array, because ls-hpack left it NULL
    // and the first growth did memcpy(new, NULL + 0, 0) - undefined
    // twice over, and two UBSan reports on the first h2 request this
    // server ever answered. deps/ls-hpack is pinned at the fork's
    // fix-undefined-behaviour branch, where lshpack_arr_push guards the
    // copy on nelem. The pin moves to a release when upstream takes the
    // three fixes (tools/webmachine-fuzz/ls-hpack).
}

H2State::~H2State()
{
    for (H2Stream &s : streams)
        content_retire(s);
    content_drain();
    lshpack_enc_cleanup(&enc);
    lshpack_dec_cleanup(&dec);
}

H2Stream *H2State::find(uint32_t stream_id)
{
    for (H2Stream &st : streams)
        if (st.id == stream_id)
            return &st;
    return nullptr;
}

H2Stream &H2State::open(uint32_t stream_id)
{
    if (H2Stream *st = find(stream_id))
        return *st;
    streams.emplace_back();
    H2Stream &conn = streams.back();
    conn.id = stream_id;
    conn.flow_window = peer_initial_window;
    return conn;
}

void H2State::content_retire(H2Stream &sqe)
{
    if (sqe.response_content.mrb != nullptr) {
        retired.push_back(Lend{sqe.response_content.mrb, sqe.response_content.value});
        sqe.response_content.mrb = nullptr;
    }
    sqe.response_content.clear();
}

void H2State::content_drain()
{
    for (const Lend &l : retired)
        resource_body_unlend(l.mrb, l.v);
    retired.clear();
}

void H2State::close_stream(uint32_t stream_id)
{
    for (size_t i = 0; i < streams.size(); i++) {
        if (streams[i].id == stream_id) {
            // The move-assign below discards this entry's members: a body it
            // still holds has to leave first, or its root leaks silently on
            // every close - RST_STREAM, END_STREAM and error paths alike.
            content_retire(streams[i]);
            // WHATWG HTML: the resource hears that its stream ended, once,
            // however it ended.
            if (streams[i].sse != nullptr) {
                sse_free(streams[i].sse);
                streams[i].sse = nullptr;
            }
            // RFC 6455 7: and the same for a WebSocket, which hears on_close.
            if (streams[i].ws != nullptr) {
                ws_free(streams[i].ws);
                streams[i].ws = nullptr;
            }
            streams[i] = std::move(streams.back());
            streams.pop_back();
            return;
        }
    }
}

} // namespace webmachine
