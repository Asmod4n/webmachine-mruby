#ifndef WEBMACHINE_TEST_HTTP_HPP
#define WEBMACHINE_TEST_HTTP_HPP

#include <mruby.h>

#include "../src/http.hpp"

namespace
{

mrb_value spec_is_tchar(mrb_state *mrb, mrb_value)
{
    mrb_int byte = 0;
    mrb_get_args(mrb, "i", &byte);
    return mrb_bool_value(http::is_tchar(static_cast<char>(byte)));
}

} // namespace

inline void http_spec(mrb_state *mrb)
{
    struct RClass *wm = mrb_module_get(mrb, "Webmachine");
    struct RClass *sp = mrb_define_module_under(mrb, wm, "SpecHttp");
    mrb_define_module_function(mrb, sp, "tchar?", spec_is_tchar, MRB_ARGS_REQ(1));
}

#endif
