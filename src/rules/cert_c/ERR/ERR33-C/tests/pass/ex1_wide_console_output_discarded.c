/*
 * Rule: ERR33-C
 * Status: PASS - ERR33-C-EX1 names the wide file-output functions alongside
 * the narrow ones: fwprintf(), vfwprintf(), fputwc() and fputws() may be
 * discarded when the output is directed to stdout or stderr. puts() and
 * putchar() are in EX1's table of functions whose results need not be
 * checked, so a stored and untested result is not reported either.
 */

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>

void f(const wchar_t *s, const wchar_t *fmt, va_list ap) {
    fwprintf(stderr, L"%ls\n", s);
    vfwprintf(stdout, fmt, ap);
    fputwc(L'x', stdout);
    fputws(s, stderr);
    int r = puts("done");
    int c = putchar('\n');
}
