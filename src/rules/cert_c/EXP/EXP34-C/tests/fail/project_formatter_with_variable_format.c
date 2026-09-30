/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * log_msg() hands its format to vfprintf(), so it is an ISO C formatter.
 * The format here is held in a variable, so no slot can be read, and a
 * possibly-null getenv() result in its tail is reported.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void show_home(const char *pattern) {
    char *home = getenv("HOME");
    log_msg(pattern, home);
}
