/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * A tentative `static int flag;` in one arm is 0 where that arm compiles,
 * so flag has no single value and the read of x is not pruned.
 */

#include <stdio.h>

#ifdef FAST
static int flag;
#else
static int flag = 1;
#endif

void report(void) {
    int x;
    if (!flag) {
        printf("%d\n", x);
    }
}
