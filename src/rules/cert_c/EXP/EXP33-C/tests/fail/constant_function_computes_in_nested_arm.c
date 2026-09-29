/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * flag() computes in a nested #else arm, so it is no constant in the
 * configuration A without B, and the read of x is not pruned.
 */

#include <stdio.h>

static int counter;

#ifdef A
#ifdef B
static int flag(void) {
    return 0;
}
#else
static int flag(void) {
    return counter++;
}
#endif
#else
static int flag(void) {
    return 0;
}
#endif

void report(void) {
    int x;
    if (flag()) {
        printf("%d\n", x);
    }
}
