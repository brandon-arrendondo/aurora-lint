/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * flag() returns 0 in the #if arm and computes in the #elif arm: every arm
 * is read, and the computing one leaves flag() no constant.
 */

#include <stdio.h>

static int counter;

#if defined(FAST)
static int flag(void) {
    return 0;
}
#elif defined(SLOW)
static int flag(void) {
    return counter;
}
#endif

void report(void) {
    int x;
    if (flag()) {
        printf("%d\n", x);
    }
}
