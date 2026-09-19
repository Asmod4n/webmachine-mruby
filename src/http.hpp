#ifndef WEBMACHINE_HTTP_HPP
#define WEBMACHINE_HTTP_HPP

#include <array>
#include <cstddef>
#include <exception>
#include <format>
#include <span>
#include <string_view>

namespace http
{

class ParseError : public std::exception
{
public:
    ParseError(const std::string_view section, const std::string_view rule,
               const std::string_view allowed, const std::string_view text, const size_t offset)
        : section_(section), rule_(rule), allowed_(allowed), offset_(offset),
          found_byte_(offset < text.size() ? static_cast<unsigned char>(text[offset]) : 0)
    {
        static constexpr std::string_view digits = "0123456789abcdef";
        const size_t from = offset < 16 ? 0 : offset - 16;
        for (const char letter : text.substr(from, 32)) {
            const unsigned char byte = static_cast<unsigned char>(letter);
            if (byte == '"' || byte == '\\') {
                excerpt_[excerpt_length_++] = '\\';
                excerpt_[excerpt_length_++] = static_cast<char>(byte);
            } else if (byte >= 0x20 && byte <= 0x7E) {
                excerpt_[excerpt_length_++] = static_cast<char>(byte);
            } else {
                excerpt_[excerpt_length_++] = '\\';
                excerpt_[excerpt_length_++] = 'x';
                excerpt_[excerpt_length_++] = digits[byte >> 4];
                excerpt_[excerpt_length_++] = digits[byte & 0x0F];
            }
        }
        const auto written = std::format_to_n(
            message_.data(), message_.size() - 1,
            "{} {}: byte {} is 0x{:02x}. The rule allows {}. Text: \"{}\"", section, rule, offset,
            found_byte_, allowed, excerpt());
        *written.out = '\0';
    }

    const char *what() const noexcept override { return message_.data(); }
    std::string_view section() const noexcept { return section_; }
    std::string_view rule() const noexcept { return rule_; }
    std::string_view allowed() const noexcept { return allowed_; }
    size_t offset() const noexcept { return offset_; }
    unsigned char found_byte() const noexcept { return found_byte_; }
    std::string_view excerpt() const noexcept { return {excerpt_.data(), excerpt_length_}; }

private:
    std::string_view section_;
    std::string_view rule_;
    std::string_view allowed_;
    std::array<char, 384> message_{};
    std::array<char, 128> excerpt_{};
    size_t offset_;
    size_t excerpt_length_ = 0;
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
