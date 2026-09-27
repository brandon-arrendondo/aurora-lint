/*
 * Rule: ERR33-C
 * Status: FAIL - fprintf() to a stream that is not stdout or stderr is not
 * covered by ERR33-C-EX1; its result must be checked.
 */

#include <stdio.h>

void f(FILE *out) {
    fprintf(out, "x\n");
}
