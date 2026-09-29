/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should not trigger EXP33-C violation
 *
 * An initialized definition followed by a tentative one: flag is still 5,
 * so the read of x is pruned.
 */

#include <stdio.h>

static int flag = 5;
static int flag;

void report(void) {
    int x;
    if (!flag) {
        printf("%d\n", x);
    }
}
