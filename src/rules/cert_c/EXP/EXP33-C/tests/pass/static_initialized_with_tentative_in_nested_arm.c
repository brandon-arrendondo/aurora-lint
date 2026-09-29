/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should not trigger EXP33-C violation
 *
 * The initializer outside the arm is compiled in every configuration that
 * compiles the tentative definition inside it, so flag is 5 everywhere.
 */

#include <stdio.h>

static int flag = 5;
#ifdef FAST
static int flag;
#endif

void report(void) {
    int x;
    if (!flag) {
        printf("%d\n", x);
    }
}
