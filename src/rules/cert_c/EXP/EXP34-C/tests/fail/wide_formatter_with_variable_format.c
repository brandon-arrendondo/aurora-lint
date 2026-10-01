/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * log_wide() hands its format to vfwprintf(), the wide ISO C formatter,
 * so it is a formatter through ISO C just as one over vfprintf() is. The
 * format is held in a variable, and a possibly-null tail argument is
 * reported.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

void log_wide(const wchar_t *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfwprintf(stderr, fmt, ap);
    va_end(ap);
}

void show_home(const wchar_t *pattern) {
    char *home = getenv("HOME");
    log_wide(pattern, home);
}
