/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * log_msg() hands its format to log_v(), which hands it to vfprintf().
 * The `%s` conversion is therefore ISO C's, which reads the string, and a
 * possibly-null getenv() result reaching it is dereferenced.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void log_v(const char *fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
}

void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_v(fmt, ap);
    va_end(ap);
}

void show_home(void) {
    char *home = getenv("HOME");
    log_msg("home is %s\n", home);
}
