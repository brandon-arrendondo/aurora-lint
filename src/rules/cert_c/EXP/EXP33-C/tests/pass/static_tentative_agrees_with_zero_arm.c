/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should not trigger EXP33-C violation
 *
 * A tentative `static int flag;` is initialized to 0 (C11 6.9.2p2), the
 * value the other arm gives it, so flag is 0 in every configuration and
 * the read of x is pruned.
 */

#include <stdio.h>

#ifdef FAST
static int flag;
#else
static int flag = 0;
#endif

void report(void) {
    int x;
    if (flag) {
        printf("%d\n", x);
    }
}
