/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * Companion to the string-literal fixtures: a real allocator call, bare or
 * seen through a cast and parentheses, still leaves the block uninitialized.
 */

#include <stdlib.h>

char bare(void) {
    char *p = malloc(8);
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}

char cast_and_parens(void) {
    char *p = (char *)(malloc(8));
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}
