/*
 * Rule: ERR33-C
 * Status: FAIL - fputs() to a stream that is not stdout or stderr is not
 * covered by ERR33-C-EX1.
 */

#include <stdio.h>

void f(FILE *out, const char *s) {
    fputs(s, out);
}
