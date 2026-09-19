#ifndef WEBMACHINE_TEST_HTTP_HPP
#define WEBMACHINE_TEST_HTTP_HPP

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/cpp_to_mrb_value.hpp>

#include "../src/http.hpp"

namespace
{

mrb_value spec_is_tchar(mrb_state *mrb, mrb_value)
{
    mrb_int byte = 0;
    mrb_get_args(mrb, "i", &byte);
    return mrb_bool_value(http::is_tchar(static_cast<char>(byte)));
}

mrb_value spec_parse_error(mrb_state *mrb, mrb_value)
{
    mrb_int problem = 0;
    const char *text = nullptr;
    mrb_int length = 0;
    mrb_int offset = 0;
    mrb_get_args(mrb, "isi", &problem, &text, &length, &offset);
    const http::ParseError error(static_cast<uint16_t>(problem),
                                 std::string_view(text, static_cast<size_t>(length)),
                                 static_cast<size_t>(offset));
    mrb_value out[8] = {
        cpp_to_mrb_value(mrb, error.section()),    cpp_to_mrb_value(mrb, error.rule()),
        cpp_to_mrb_value(mrb, error.title()),      cpp_to_mrb_value(mrb, error.allowed()),
        cpp_to_mrb_value(mrb, error.status()),     cpp_to_mrb_value(mrb, error.offset()),
        cpp_to_mrb_value(mrb, error.found_byte()), cpp_to_mrb_value(mrb, error.excerpt()),
    };
    return mrb_ary_new_from_values(mrb, 8, out);
}

} // namespace

inline void http_spec(mrb_state *mrb)
{
    struct RClass *wm = mrb_module_get(mrb, "Webmachine");
    struct RClass *sp = mrb_define_module_under(mrb, wm, "SpecHttp");
    mrb_define_module_function(mrb, sp, "tchar?", spec_is_tchar, MRB_ARGS_REQ(1));
    mrb_define_module_function(mrb, sp, "parse_error", spec_parse_error, MRB_ARGS_REQ(3));
}

#endif
