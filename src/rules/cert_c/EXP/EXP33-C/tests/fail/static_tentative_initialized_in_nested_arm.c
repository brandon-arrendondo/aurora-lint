/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * flag is 0 where FAST is not defined and 5 where it is, so it has no
 * single value and the read of x is not pruned.
 */

#include <stdio.h>

static int flag;
#ifdef FAST
static int flag = 5;
#endif

void report(void) {
    int x;
    if (!flag) {
        printf("%d\n", x);
    }
}
