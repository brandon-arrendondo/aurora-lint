/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: used writes through its out-parameter only when it is non-null,
 * and every call here passes a null pointer constant, directly or through
 * peak. A write through a null pointer never happens in a defined
 * execution, so neither call changes anything.
 */

#include <stddef.h>

#define TWICE(x) ((x) + (x))

static int used(int *high) {
    if (high) {
        *high = 3;
    }
    return 1;
}

static int peak(void) {
    return used(NULL);
}

int use(void) {
    return TWICE(used(0)) + TWICE(used((void *)0)) + TWICE(peak());
}
