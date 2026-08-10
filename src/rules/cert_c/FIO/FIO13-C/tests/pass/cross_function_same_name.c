/*
 * Rule: FIO13-C
 * Source: task 408 regression
 * Status: PASS - Should NOT trigger FIO13-C violation
 *
 * Two different functions each declare a same-named FILE* parameter
 * ("fp"). Each function's single ungetc() call is compliant on its own
 * (no successive ungetc without an intervening read within that
 * function). Prior to the per-function scoping fix, the two functions'
 * ungetc calls were merged into one file-wide timeline keyed on "fp",
 * causing the second function's ungetc to be flagged as "successive"
 * with the first function's unrelated ungetc call.
 */

#include <stdio.h>

void first_reader(FILE *fp) {
    int ch;

    ungetc('a', fp);
    ch = fgetc(fp);
    (void)ch;
}

void second_reader(FILE *fp) {
    /* COMPLIANT in isolation: this is the only ungetc on this fp within
     * this function. */
    ungetc('b', fp);
}
