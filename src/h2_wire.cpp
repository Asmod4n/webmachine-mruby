#include "h2_wire.hpp"

namespace webmachine
{
void h2_put_frame_header(unsigned char *bytes, H2FrameHead facts)
{
    const uint32_t len = facts.len;
    const uint32_t stream = facts.stream;
    bytes[0] = static_cast<unsigned char>(len >> 16);
    bytes[1] = static_cast<unsigned char>(len >> 8);
    bytes[2] = static_cast<unsigned char>(len);
    bytes[3] = facts.type;
    bytes[4] = facts.flags;
    bytes[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
    bytes[6] = static_cast<unsigned char>(stream >> 16);
    bytes[7] = static_cast<unsigned char>(stream >> 8);
    bytes[8] = static_cast<unsigned char>(stream);
}

void h2_patch_stream_id(unsigned char *bytes, uint32_t stream)
{
    bytes[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
    bytes[6] = static_cast<unsigned char>(stream >> 16);
    bytes[7] = static_cast<unsigned char>(stream >> 8);
    bytes[8] = static_cast<unsigned char>(stream);
}

uint32_t h2_u24(const unsigned char *bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 16) | (static_cast<uint32_t>(bytes[1]) << 8) |
           bytes[2];
}

uint32_t h2_u32(const unsigned char *bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3];
}

uint32_t h2_u31(const unsigned char *bytes)
{
    return h2_u32(bytes) & 0x7fffffff;
}

uint16_t h2_u16(const unsigned char *bytes)
{
    return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
}

bool h2_enc_field(H2BlockOut out, const H2Field &facts)
{
    const size_t nlen = facts.name.size();
    const size_t vlen = facts.value.size();
    // Nothing is checked here, and that is deliberate: what an app can
    // shape is checked where it enters the header buffer - http::
    // field_name_ok / field_value_ok, at response.cpp's Headers#[]= and at
    // resource.cpp's `field`. By the time a line reaches this encoder it
    // has already passed that gate, so a second check would guard against
    // something no user can reach. The pointers cannot be null either:
    // they are our own literals and std::string::data().
    char hbuf[512];
    if (nlen + 2 + vlen > sizeof(hbuf))
        return false;
    std::memcpy(hbuf, facts.name.data(), nlen);
    hbuf[nlen] = ':';
    hbuf[nlen + 1] = ' ';
    std::memcpy(hbuf + nlen + 2, facts.value.data(), vlen);
    lsxpack_header_t xh;
    lsxpack_header_set_offset2(&xh, hbuf, 0, nlen, nlen + 2, vlen);
    // lshpack.c: indexed_type 0 = with incremental indexing, 1 = without,
    // 2 = never indexed. 1 is the one RFC 7541 6.2.2 describes and the one
    // a replayed block needs; NEVER_INDEX (6.2.3) would say "sensitive",
    // which a Date is not.
    if (!facts.index)
        xh.indexed_type = 1;
    unsigned char *next_out = lshpack_enc_encode(out.enc, out.at, out.end, &xh);
    if (next_out == out.at)
        return false;
    out.at = next_out;
    return true;
}
} // namespace webmachine
