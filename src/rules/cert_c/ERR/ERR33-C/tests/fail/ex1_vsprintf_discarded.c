/*
 * Rule: ERR33-C
 * Status: FAIL - vsprintf() is not in ERR33-C-EX1.
 */

#include <stdarg.h>
#include <stdio.h>

void f(char *buf, const char *fmt, va_list ap) {
    vsprintf(buf, fmt, ap);
}
