// mruby offers RSTRING_PTR, RSTRING_LEN, RARRAY_PTR and RARRAY_LEN, and
// they are macros. A macro has no type, it can read its argument twice,
// and no language server can find its callers. So the macros are spelled
// in ruby_value.cpp and nowhere else.
#ifndef WEBMACHINE_RUBY_VALUE_HPP
#define WEBMACHINE_RUBY_VALUE_HPP

#include "webmachine.hpp"

#include <string_view>

namespace webmachine
{
std::string_view ruby_string_bytes(mrb_value ruby_string);

size_t ruby_string_length(mrb_value ruby_string);

// RFC 9110 5.5: may the bytes of this String stand as a field value?
bool ruby_string_is_field_value(mrb_value ruby_string);

// RFC 9110 5.6.2: may the bytes of this String stand as a field name?
bool ruby_string_is_field_name(mrb_value ruby_string);

// RFC 9110 5.1: a field name compares case-insensitively, so a name used
// as a Hash key is folded before it is frozen.
void ruby_string_lowercase_in_place(mrb_value ruby_string);

bool ruby_string_holds_octet(mrb_value ruby_string, char octet);

size_t ruby_array_length(mrb_value ruby_array);

const mrb_value *ruby_array_items(mrb_value ruby_array);

mrb_value ruby_array_entry(mrb_value ruby_array, size_t index);
} // namespace webmachine

#endif // WEBMACHINE_RUBY_VALUE_HPP
