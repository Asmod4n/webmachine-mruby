// Nothing in src/ drives http.hpp yet, so mrbtest is where its tables
// and its error record are exercised.

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/string.h>

#include "../src/http.hpp"

namespace
{

// RFC 9110 5.6.2: ':' and '(' are not tchar. RFC 2616 called them
// separators, and that word is gone.
static_assert(http::is_tchar('a'));
static_assert(http::is_tchar('Z'));
static_assert(http::is_tchar('0'));
static_assert(http::is_tchar('!'));
static_assert(http::is_tchar('~'));
static_assert(!http::is_tchar(':'));
static_assert(!http::is_tchar('('));
static_assert(!http::is_tchar(' '));
static_assert(!http::is_tchar('\t'));
static_assert(!http::is_tchar('"'));
static_assert(!http::is_tchar('\0'));
static_assert(!http::is_tchar(static_cast<char>(0x80)));

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
    mrb_value out[8];
    out[0] = mrb_str_new(mrb, error.section().data(), error.section().size());
    out[1] = mrb_str_new(mrb, error.rule().data(), error.rule().size());
    out[2] = mrb_str_new(mrb, error.title().data(), error.title().size());
    out[3] = mrb_str_new(mrb, error.allowed().data(), error.allowed().size());
    out[4] = mrb_int_value(mrb, static_cast<mrb_int>(error.status()));
    out[5] = mrb_int_value(mrb, static_cast<mrb_int>(error.offset()));
    out[6] = mrb_int_value(mrb, error.found_byte());
    out[7] = mrb_str_new(mrb, error.excerpt().data(), error.excerpt().size());
    return mrb_ary_new_from_values(mrb, 8, out);
}

mrb_value spec_parse_error_what(mrb_state *mrb, mrb_value)
{
    mrb_int problem = 0;
    mrb_get_args(mrb, "i", &problem);
    const http::ParseError error(static_cast<uint16_t>(problem), "", 0);
    return mrb_str_new_cstr(mrb, error.what());
}

mrb_value spec_parse_error_size(mrb_state *mrb, mrb_value)
{
    return mrb_int_value(mrb, static_cast<mrb_int>(sizeof(http::ParseError)));
}

} // namespace

void wm_http_gem_test(mrb_state *mrb)
{
    struct RClass *wm = mrb_module_get_id(mrb, mrb_intern_lit(mrb, "Webmachine"));
    struct RClass *sp = mrb_define_module_under_id(mrb, wm, mrb_intern_lit(mrb, "SpecHttp"));
    mrb_define_module_function_id(mrb, sp, mrb_intern_lit(mrb, "parse_error"), spec_parse_error,
                                  MRB_ARGS_REQ(3));
    mrb_define_module_function_id(mrb, sp, mrb_intern_lit(mrb, "parse_error_what"),
                                  spec_parse_error_what, MRB_ARGS_REQ(1));
    mrb_define_module_function_id(mrb, sp, mrb_intern_lit(mrb, "parse_error_size"),
                                  spec_parse_error_size, MRB_ARGS_NONE());
}
