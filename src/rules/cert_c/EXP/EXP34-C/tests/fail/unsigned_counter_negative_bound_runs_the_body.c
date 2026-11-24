/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * Compared with an unsigned counter, -1 converts to UINT_MAX, so the
 * loop runs and dereferences the null pointer. The header does not prove
 * the body dead.
 */
#include <stddef.h>

#define NEGC (-1)

void literal(void) {
    int *p = NULL;
    unsigned k;
    for (k = 0; k < (-1); k++) {
        *p = 1;
    }
}

void named(void) {
    int *p = NULL;
    unsigned k;
    for (k = 0; k < NEGC; k++) {
        *p = 1;
    }
}
