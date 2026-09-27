/*
 * Rule: ERR33-C
 * Status: PASS - ERR33-C-EX1: printf(), vprintf(), puts() and putchar() may
 * always be discarded, and the fprintf and file-output families may be
 * discarded when the output is directed to stdout or stderr.
 */

#include <stdarg.h>
#include <stdio.h>

void f(const char *s, const char *fmt, va_list ap) {
    printf("%s\n", s);
    vprintf(fmt, ap);
    puts(s);
    putchar('x');
    fprintf(stdout, "%s\n", s);
    fprintf(stderr, "%s\n", s);
    fprintf((stderr), "%s\n", s);
    vfprintf(stderr, fmt, ap);
    fputs(s, stdout);
    fputs(s, stderr);
    fputc('x', stdout);
    fputc('x', stderr);
}
