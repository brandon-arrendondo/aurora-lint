/*
 * Rule: FIO39-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO39-C violation
 *
 * Input then output without positioning call
 */

#include <stdio.h>

void input_then_output(FILE *fp) {
    char buf[64];
    /* VIOLATION: fread followed by fwrite without positioning */
    fread(buf, 1, sizeof(buf), fp);
    fwrite(buf, 1, sizeof(buf), fp);
}
