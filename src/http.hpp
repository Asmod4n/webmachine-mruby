#ifndef WEBMACHINE_HTTP_HPP
#define WEBMACHINE_HTTP_HPP

#include <cstddef>
#include <span>
#include <string_view>

namespace http
{

struct Request;

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
