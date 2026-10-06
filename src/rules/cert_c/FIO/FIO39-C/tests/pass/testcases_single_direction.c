/*
 * Rule: FIO39-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO39-C violation
 *
 * All operations in same direction (output only)
 */

#include <stdio.h>

void output_only(FILE *fp) {
    /* COMPLIANT: no alternation — all output */
    fprintf(fp, "line 1\n");
    fprintf(fp, "line 2\n");
    fputs("line 3\n", fp);
}
