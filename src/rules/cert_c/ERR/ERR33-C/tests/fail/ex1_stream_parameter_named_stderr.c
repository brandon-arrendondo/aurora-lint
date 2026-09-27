/*
 * Rule: ERR33-C
 * Status: FAIL - the stream is a parameter that happens to be named stderr;
 * it may be any file, so ERR33-C-EX1 does not cover the discarded result.
 */

#include <stdio.h>

void f(FILE *stderr) {
    fputs("x", stderr);
}
