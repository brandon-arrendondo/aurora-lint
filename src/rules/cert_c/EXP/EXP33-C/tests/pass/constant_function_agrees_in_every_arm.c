/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger EXP33-C violation
 *
 * flag() returns 0 in every configuration, so it folds and the branch
 * reading the uninitialized x is dead.
 */

#include <stdio.h>

#ifdef FAST
static int flag(void) {
    return 0;
}
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
