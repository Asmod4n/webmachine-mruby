#include "h2_wire.hpp"

namespace webmachine
{
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
