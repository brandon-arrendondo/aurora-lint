/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The #elifdef arm is read too: flag is 1 under FAST and 0 under SLOW, so
 * it has no single value and the read of x is not pruned.
 */

#include <stdio.h>

#ifdef FAST
static const int flag = 1;
#elifdef SLOW
static const int flag = 0;
#endif

void report(void) {
    int x;
    if (!flag) {
        printf("%d\n", x);
    }
}
