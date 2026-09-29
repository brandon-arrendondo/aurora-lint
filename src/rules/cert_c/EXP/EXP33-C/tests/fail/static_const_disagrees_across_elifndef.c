/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The #elifndef arm is read too: flag is 1 under FAST and 0 without SLOW,
 * so it has no single value and the read of x is not pruned.
 */

#include <stdio.h>

#ifdef FAST
static const int flag = 1;
#elifndef SLOW
static const int flag = 0;
#endif

void report(void) {
    int x;
    if (!flag) {
        printf("%d\n", x);
    }
}
