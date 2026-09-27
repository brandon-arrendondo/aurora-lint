/*
 * Rule: ERR33-C
 * Status: FAIL - fputc() to a stream that is not stdout or stderr is not
 * covered by ERR33-C-EX1.
 */

#include <stdio.h>

void f(FILE *out) {
    fputc('x', out);
}
