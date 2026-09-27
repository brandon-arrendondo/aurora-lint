/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: putc may evaluate its stream argument more than once
 * (C11 7.21.7.8).
 */

#include <stdio.h>

void r(FILE **fps, int c) {
    int i = 0;
    putc(c, fps[i++]);  // VIOLATION
}
