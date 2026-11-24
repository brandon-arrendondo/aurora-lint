/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should not trigger EXP34-C violation
 *
 * The header's start already fails its test, so the body that would
 * dereference the null pointer never runs.
 */
#include <stddef.h>

void f(void) {
    int *p = NULL;
    int k;
    for (k = 5; k < 3; k++) {
        *p = 1;
    }
}
