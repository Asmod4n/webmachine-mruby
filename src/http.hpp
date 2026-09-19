#ifndef WEBMACHINE_HTTP_HPP
#define WEBMACHINE_HTTP_HPP

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

namespace http
{

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
