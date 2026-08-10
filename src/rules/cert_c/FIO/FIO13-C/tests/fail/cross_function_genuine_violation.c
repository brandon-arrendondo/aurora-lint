/*
 * Rule: FIO13-C
 * Source: task 408 regression
 * Status: FAIL - Should trigger FIO13-C violation (exactly once)
 *
 * Two functions each use a same-named FILE* parameter ("fp"). The first
 * function is compliant (single ungetc). The second function has a
 * genuine violation: two successive ungetc() calls with no intervening
 * read. Per-function scoping must still catch the real violation in
 * second_function without letting the first function's clean ungetc
 * mask or duplicate it.
 */

#include <stdio.h>

void clean_function(FILE *fp) {
    int ch;

    ungetc('a', fp);
    ch = fgetc(fp);
    (void)ch;
}

void second_function(FILE *fp) {
    /* VIOLATION: successive ungetc without intervening read */
    ungetc('x', fp);
    ungetc('y', fp);
}
