/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should not trigger EXP33-C violation
 *
 * A tentative definition followed by an initialized one: flag is 5, not
 * 0, so the read of x is pruned.
 */

#include <stdio.h>

static int flag;
static int flag = 5;

void report(void) {
    int x;
    if (!flag) {
        printf("%d\n", x);
    }
}
