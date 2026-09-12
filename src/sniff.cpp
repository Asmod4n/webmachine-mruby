// RFC-free, and that is the point: no RFC says what octets a media type
// begins with. The WHATWG MIME Sniffing Standard does -
// https://mimesniff.spec.whatwg.org/ - and its pattern tables are what
// this file carries.
//
// What it is for: a client names a media type in Content-Type and then
// sends something else. `sniff: true` on a content_types_accepted row
// asks the server to check the claim against the octets, and to refuse
// at the first buffer rather than after half a gigabyte.
//
// What it is not: file(1). libmagic reads a compiled database in a DSL
// and carries hand-written parsers for JSON and CSV, and those parsers
// are where its CVEs came from. There is nothing to parse here. A row is
// an offset, a byte pattern and a type; the whole engine is one
// comparison that checks its bounds, and every row goes through it.
//
// The table was written from the specification and checked against the
// table of the `infer` crate where the two overlap.

#include "webmachine.hpp"

#include <string>
#include <vector>

namespace webmachine
{
namespace sniff
{
namespace
{

// A row of the table. `at` is where the pattern has to sit, counted from
// the first octet of the body.
struct Pattern {
    uint16_t pattern_sits_at;
    std::string_view bytes;
    std::string_view type;
    // A container carries other formats: a zip is a docx, an epub, a jar
    // and an odt as well, and a gzip is a tar.gz. So a container that
    // matches never contradicts a declaration - it only fails to confirm
    // one.
    bool container;
};

// The one place an offset and a length meet. Every row goes through it,
// so no row can get its own bounds wrong.
bool at(std::string_view body_start, size_t offset, std::string_view pattern)
{
    return body_start.size() >= offset + pattern.size() &&
           body_start.compare(offset, pattern.size(), pattern) == 0;
}

constexpr Pattern kTable[] = {
    // Images.
    {0, std::string_view("\x89PNG\r\n\x1a\n", 8), "image/png", false},
    {0, std::string_view("\xff\xd8\xff", 3), "image/jpeg", false},
    {0, "GIF87a", "image/gif", false},
    {0, "GIF89a", "image/gif", false},
    {0, "BM", "image/bmp", false},
    {0, std::string_view("\x00\x00\x01\x00", 4), "image/vnd.microsoft.icon", false},
    {0, std::string_view("II*\x00", 4), "image/tiff", false},
    {0, std::string_view("MM\x00*", 4), "image/tiff", false},
    {0, "<?xml", "image/svg+xml", true},
    // Audio and video. RIFF and ftyp carry their real type further in,
    // so each form is its own row.
    {8, "WEBP", "image/webp", false},
    {8, "WAVE", "audio/wav", false},
    {8, "AVI ", "video/x-msvideo", false},
    {0, "OggS", "audio/ogg", false},
    {0, "fLaC", "audio/flac", false},
    {0, "ID3", "audio/mpeg", false},
    {0, std::string_view("\xff\xfb", 2), "audio/mpeg", false},
    {0, std::string_view("\x1a\x45\xdf\xa3", 4), "video/webm", true},
    {4, "ftypqt", "video/quicktime", false},
    {4, "ftyp", "video/mp4", false},
    {0, std::string_view("\x00\x00\x01\xba", 4), "video/mpeg", false},
    // Documents and archives.
    {0, "%PDF-", "application/pdf", false},
    {0, "%!PS-Adobe-", "application/postscript", false},
    {0, "PK\x03\x04", "application/zip", true},
    {0, std::string_view("\x1f\x8b\x08", 3), "application/gzip", true},
    {0, "BZh", "application/x-bzip2", true},
    {0,
     std::string_view("\xfd"
                      "7zXZ\x00",
                      6),
     "application/x-xz", true},
    {0, std::string_view("7z\xbc\xaf\x27\x1c", 6), "application/x-7z-compressed", true},
    {0, std::string_view("Rar!\x1a\x07", 6), "application/vnd.rar", true},
    {257, "ustar", "application/x-tar", true},
    {0,
     std::string_view("\x00"
                      "asm",
                      4),
     "application/wasm", false},
    // Fonts.
    {0, "wOFF", "font/woff", false},
    {0, "wOF2", "font/woff2", false},
    {0, "OTTO", "font/otf", false},
    {0, std::string_view("\x00\x01\x00\x00", 4), "font/ttf", false},
};

// The type a declaration names, without its parameters and folded to
// lower case for the comparison. The header reader already gave us the
// value; this only cuts the parameters off.
std::string_view media_type_without_parameters(std::string_view declared)
{
    const size_t semi = declared.find(';');
    std::string_view without_parameters =
        semi == std::string_view::npos ? declared : declared.substr(0, semi);
    while (!without_parameters.empty() &&
           (without_parameters.back() == ' ' || without_parameters.back() == '\t'))
        without_parameters.remove_suffix(1);
    return without_parameters;
}

bool media_type_is_same(std::string_view one, std::string_view other)
{
    if (one.size() != other.size())
        return false;
    for (size_t i = 0; i < one.size(); i++) {
        const char folded =
            one[i] >= 'A' && one[i] <= 'Z' ? static_cast<char>(one[i] + 32) : one[i];
        if (folded != other[i])
            return false;
    }
    return true;
}
} // namespace

// Does this server hold a pattern for that type? The fold asks it, so a
// resource that writes `sniff: true` beside a type nothing can confirm
// is refused while the app is being set up rather than at a request.
bool knows_media_type(std::string_view declared)
{
    const std::string_view want = media_type_without_parameters(declared);
    for (const Pattern &p : kTable) {
        if (media_type_is_same(want, p.type))
            return true;
    }
    return false;
}

// Did this resource ask for that claim to be checked? The list is what
// the fold read from the content_types_accepted rows, and the claim is
// the Content-Type of the request, parameters and all.
bool was_asked_for(const std::vector<std::string> &types, std::string_view declared)
{
    const std::string_view want = media_type_without_parameters(declared);
    for (const std::string &t : types) {
        if (media_type_is_same(want, t))
            return true;
    }
    return false;
}

// How many octets the table can read. The deepest row is the tar
// header at 257, and nothing here looks further.
size_t octets_needed()
{
    return 512;
}

// What the octets say about the claim.
//
// Two directions, because the interesting lie is in the second one.
//
//   The declared type is one this table knows - image/png, video/mp4.
//   Then the octets have to match it. A JPEG declared as a PNG is a
//   contradiction even though both are images.
//
//   The declared type is one the table cannot confirm - text/plain,
//   application/json, a docx. Then the question is what the octets are
//   instead: a pattern that names a concrete format contradicts the
//   claim, and a container never does, because a zip is a docx as much
//   as it is a jar.
//
// Anything else is kUnknown, and kUnknown never refuses a request. A
// check that guesses would refuse honest clients, which is worse than
// letting a liar through to max_body.
Verdict check_declaration(std::string_view declared, std::string_view head)
{
    const std::string_view want = media_type_without_parameters(declared);
    const bool declared_known = knows_media_type(want);
    for (const Pattern &p : kTable) {
        if (!at(head, p.pattern_sits_at, p.bytes))
            continue;
        if (media_type_is_same(want, p.type))
            return Verdict::kAgrees;
        if (declared_known)
            return Verdict::kContradicts;
        if (!p.container)
            return Verdict::kContradicts;
        return Verdict::kUnknown;
    }
    // Nothing matched. A type this table knows has to have matched, so
    // the claim is wrong - but only once enough octets have arrived to
    // say so.
    if (declared_known && head.size() >= octets_needed())
        return Verdict::kContradicts;
    return Verdict::kUnknown;
}
} // namespace sniff
} // namespace webmachine
