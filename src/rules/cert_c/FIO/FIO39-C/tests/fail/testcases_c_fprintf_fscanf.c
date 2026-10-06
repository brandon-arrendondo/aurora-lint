/*
 * Rule: FIO39-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO39-C violation
 *
 * C-style output then input without positioning call
 */

#include <stdio.h>

void alternating_io_c(FILE *fp) {
    int value;
    /* VIOLATION: output followed by input without fflush/fseek/fsetpos/rewind */
    fprintf(fp, "data: %d\n", 42);
    fscanf(fp, "%d", &value);
}
