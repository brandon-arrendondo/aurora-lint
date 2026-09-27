/*
 * Rule: ERR33-C
 * Status: PASS - ERR33-C-EX1: printf() and vprintf() may always be
 * discarded, and the fprintf and file-output families may be discarded when
 * the output is directed to stdout or stderr, named directly, in
 * parentheses, through an object-like alias, or past a comment.
 */

#include <stdarg.h>
#include <stdio.h>

#define MSG_OUT stderr

void f(const char *s, const char *fmt, va_list ap) {
    printf("%s\n", s);
    vprintf(fmt, ap);
    fprintf(stdout, "%s\n", s);
    fprintf(stderr, "%s\n", s);
    fprintf((stderr), "%s\n", s);
    vfprintf(stderr, fmt, ap);
    fputs(s, stdout);
    fputs(s, stderr);
    fputc('x', stdout);
    fputc('x', stderr);
    fputs(s, MSG_OUT);
    fputs(s /* message */, stderr);
}
