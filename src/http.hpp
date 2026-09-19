#ifndef WEBMACHINE_HTTP_HPP
#define WEBMACHINE_HTTP_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>

namespace http
{

struct Problem {
    const char *section;
    const char *rule;
    const char *title;
    const char *allowed;
    unsigned status;
};

inline constexpr std::array kProblems = std::to_array<Problem>({
    {"", "", "", "", 0},
    {"RFC 9110 5.6.2", "tchar", "The field name is not valid",
     "!#$%&'*+-.^_`|~ / DIGIT / ALPHA", 400},
    {"RFC 9110 5.6.4", "quoted-string", "The field value is not valid",
     "DQUOTE *( qdtext / quoted-pair ) DQUOTE", 400},
    {"RFC 9110 5.6.4", "qdtext", "The field value is not valid",
     "HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text", 400},
});

inline constexpr uint16_t kUnknownProblem = 0;
inline constexpr uint16_t kTcharProblem = 1;
inline constexpr uint16_t kQuotedStringProblem = 2;
inline constexpr uint16_t kQdtextProblem = 3;

class ParseError : public std::runtime_error
{
public:
    ParseError(const uint16_t problem, const std::string_view text, const size_t offset)
        : std::runtime_error(kProblems[problem].title), problem_(problem),
          offset_(static_cast<uint32_t>(offset)),
          found_byte_(offset < text.size() ? static_cast<unsigned char>(text[offset]) : 0)
    {
        const size_t from = offset < 16 ? 0 : offset - 16;
        for (const char letter : text.substr(from, excerpt_.size()))
            excerpt_[excerpt_length_++] = letter;
    }

    std::string_view section() const noexcept { return kProblems[problem_].section; }
    std::string_view rule() const noexcept { return kProblems[problem_].rule; }
    std::string_view title() const noexcept { return kProblems[problem_].title; }
    std::string_view allowed() const noexcept { return kProblems[problem_].allowed; }
    unsigned status() const noexcept { return kProblems[problem_].status; }
    size_t offset() const noexcept { return offset_; }
    unsigned char found_byte() const noexcept { return found_byte_; }
    std::string_view excerpt() const noexcept { return {excerpt_.data(), excerpt_length_}; }

private:
    uint16_t problem_;
    uint32_t offset_;
    std::array<char, 32> excerpt_{};
    uint8_t excerpt_length_ = 0;
    unsigned char found_byte_;
};

inline constexpr std::array<bool, 256> kTchar = [] {
    std::array<bool, 256> table{};
    for (const char letter : std::string_view("!#$%&'*+-.^_`|~"))
        table[static_cast<unsigned char>(letter)] = true;
    for (unsigned index = '0'; index <= '9'; index++)
        table[index] = true;
    for (unsigned index = 'A'; index <= 'Z'; index++)
        table[index] = true;
    for (unsigned index = 'a'; index <= 'z'; index++)
        table[index] = true;
    return table;
}();

constexpr bool is_tchar(const char letter)
{
    return kTchar[static_cast<unsigned char>(letter)];
}

struct Field {
    std::string_view name;
    std::string_view value;
};

struct Fields {
    std::span<const Field> entries;
};

struct Request {
    std::string_view method;
    std::string_view target;
    Fields header_section;
    std::span<const std::byte> content;
    Fields trailer_section;
};

struct Uri {
    std::string_view scheme;
    std::string_view host;
    unsigned port;
    std::string_view path;
    std::string_view query;
};

struct Response {
    unsigned status;
    Fields header_section;
    std::span<const std::byte> content;
    Fields trailer_section;
};

struct Representation {
    std::string_view media_type;
    std::string_view content_coding;
    std::string_view language;
    std::string_view entity_tag;
    std::span<const std::byte> data;
};

struct Resource {
    std::string_view target;
    Representation (*select_representation)(const Request);
};

}

#endif
