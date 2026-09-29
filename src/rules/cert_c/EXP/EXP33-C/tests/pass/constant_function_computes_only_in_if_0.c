/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should not trigger EXP33-C violation
 *
 * The computing definition sits in #if 0, which no build compiles, so it is
 * no configuration: flag() is 0 in every one and the read of x is dead.
 */

#include <stdio.h>

static int counter;

#if 0
static int flag(void) {
    return counter;
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
