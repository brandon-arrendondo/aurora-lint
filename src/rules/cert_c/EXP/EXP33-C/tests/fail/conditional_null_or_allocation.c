/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The null pointer constant may be the first arm, spelled 0.
 */

#include <stdlib.h>

char conditional_null_first(size_t n) {
    char *p;
    p = n == 0 ? 0 : (char *)malloc(n);
    char c = p[0]; /* VIOLATION */
    free(p);
    return c;
}
