/*
 * Rule: ERR33-C
 * Status: FAIL - vfprintf() to a stream that is not stdout or stderr is not
 * covered by ERR33-C-EX1.
 */

#include <stdarg.h>
#include <stdio.h>

void f(FILE *out, const char *fmt, va_list ap) {
    vfprintf(out, fmt, ap);
}
