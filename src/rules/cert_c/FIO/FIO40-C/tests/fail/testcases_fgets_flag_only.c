/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO40-C violation
 *
 * fgets() failure sets an error flag but does not reset the buffer, and a
 * later read of the buffer is reachable from the failure branch.
 */

#include <stdio.h>

void fgets_flag_no_reset(FILE *fp, int verbose) {
    char buf[256];
    int error_flag = 0;
    /* VIOLATION: buffer not reset on failure, only flag set */
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        error_flag = 1;
    }
    if (verbose) {
        printf("%d %s", error_flag, buf);
    }
}
