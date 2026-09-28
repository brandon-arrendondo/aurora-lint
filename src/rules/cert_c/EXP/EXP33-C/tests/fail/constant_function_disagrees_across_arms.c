/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * flag() returns 1 in one configuration and 0 in the other, so it has no
 * one value and the branch is live in the FAST build, though the last arm
 * returns 0.
 */

#include <stdio.h>

#ifdef FAST
static int flag(void) {
    return 1;
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
