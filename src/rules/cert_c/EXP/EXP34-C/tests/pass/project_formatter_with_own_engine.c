/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * str_printf() formats with its own engine, which prints "" for a NULL
 * `%s` argument, the way sqlite's printf does. Nothing in its body hands
 * the format to an ISO C formatter, so its `%s` is not the standard's,
 * and a possibly-null argument reaching it is no dereference.
 */
#include <stdarg.h>
#include <stdlib.h>

static char out[256];

static void str_vappend(const char *fmt, va_list ap) {
    int n = 0;
    for (; *fmt && n < 255; fmt++) {
        if (fmt[0] == '%' && fmt[1] == 's') {
            const char *s = va_arg(ap, const char *);
            if (s == 0)
                s = "";
            while (*s && n < 255)
                out[n++] = *s++;
            fmt++;
        } else {
            out[n++] = *fmt;
        }
    }
    out[n] = 0;
}

char *str_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    str_vappend(fmt, ap);
    va_end(ap);
    return out;
}

char *home_path(void) {
    char *home = getenv("HOME");
    return str_printf("%s/.rc", home);
}
