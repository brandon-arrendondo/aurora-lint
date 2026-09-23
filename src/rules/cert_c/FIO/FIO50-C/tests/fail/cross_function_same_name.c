/*
 * Rule: FIO50-C
 * Task: 409
 * Status: FAIL - Should trigger FIO50-C violation
 *
 * Two different functions each use a same-named FILE* parameter ("fp").
 * The first function is fully compliant. The second function has a genuine
 * output-then-input violation with no intervening positioning call. This
 * confirms that per-function scoping (task 409) still detects a real
 * violation local to one function, rather than only ever suppressing
 * findings.
 */

#include <stdio.h>

void compliant(FILE *fp) {
    int value;
    fprintf(fp, "data: %d\n", 42);
    fflush(fp);
    fscanf(fp, "%d", &value);
}

void noncompliant(FILE *fp) {
    int value;
    /* VIOLATION: output followed by input without an intervening
     * positioning call, scoped to this function only. */
    fprintf(fp, "data: %d\n", 42);
    fscanf(fp, "%d", &value);
}
