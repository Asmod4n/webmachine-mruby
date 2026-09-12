// The one place this tree spells mruby's value macros.
#include "ruby_value.hpp"

#include <mruby/array.h>
#include <mruby/string.h>

namespace webmachine
{
std::string_view ruby_string_bytes(mrb_value ruby_string)
{
    const char *const first = RSTRING_PTR(ruby_string);
    const size_t length = static_cast<size_t>(RSTRING_LEN(ruby_string));
    return std::string_view(first, length);
}

size_t ruby_string_length(mrb_value ruby_string)
{
    return static_cast<size_t>(RSTRING_LEN(ruby_string));
}

bool ruby_string_is_field_value(mrb_value ruby_string)
{
    const std::string_view bytes = ruby_string_bytes(ruby_string);
    return http::field_value_ok(bytes.data(), bytes.size());
}

bool ruby_string_is_field_name(mrb_value ruby_string)
{
    const std::string_view bytes = ruby_string_bytes(ruby_string);
    return http::field_name_ok(bytes.data(), bytes.size());
}

bool ruby_string_holds_octet(mrb_value ruby_string, char octet)
{
    return ruby_string_bytes(ruby_string).find(octet) != std::string_view::npos;
}

size_t ruby_array_length(mrb_value ruby_array)
{
    return static_cast<size_t>(RARRAY_LEN(ruby_array));
}

mrb_value ruby_array_entry(mrb_value ruby_array, size_t index)
{
    return RARRAY_PTR(ruby_array)[index];
}
} // namespace webmachine
