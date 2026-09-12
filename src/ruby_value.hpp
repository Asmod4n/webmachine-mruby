// What a Ruby value holds, read through a function and never through a
// macro at the call site.
//
// mruby offers RSTRING_PTR, RSTRING_LEN, RARRAY_PTR and RARRAY_LEN, and
// they are macros. A macro has no type, it can read its argument twice,
// and no language server can find its callers. So the macros are spelled
// in ruby_value.cpp and nowhere else: a caller hands the value over and
// reads the answer.
#ifndef WEBMACHINE_RUBY_VALUE_HPP
#define WEBMACHINE_RUBY_VALUE_HPP

#include "webmachine.hpp"

#include <string_view>

namespace webmachine
{
// The bytes a Ruby String holds. The caller must know it is a String;
// mrb_string_p answers that question.
std::string_view ruby_string_bytes(mrb_value ruby_string);

// How many bytes a Ruby String holds.
size_t ruby_string_length(mrb_value ruby_string);

// RFC 9110 5.5: may the bytes of this String stand as a field value?
bool ruby_string_is_field_value(mrb_value ruby_string);

// RFC 9110 5.6.2: may the bytes of this String stand as a field name?
bool ruby_string_is_field_name(mrb_value ruby_string);

// Does this String carry that octet anywhere?
bool ruby_string_holds_octet(mrb_value ruby_string, char octet);

// How many entries a Ruby Array holds.
size_t ruby_array_length(mrb_value ruby_array);

// One entry of a Ruby Array, by its index. The caller must know the
// index is inside the array; ruby_array_length answers that question.
mrb_value ruby_array_entry(mrb_value ruby_array, size_t index);
} // namespace webmachine

#endif // WEBMACHINE_RUBY_VALUE_HPP
