/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * flag() returns 0 when FAST is defined, but otherwise returns a value
 * it computes. In that build the branch reading the uninitialized x runs,
 * so flag() is no constant in every configuration (ADR-0010).
 */

#include <stdio.h>

static int counter;

#ifdef FAST
static int flag(void) {
    return 0;
}
#else
static int flag(void) {
    return counter > 3;
}
#endif

void report(void) {
    int x;
    if (flag()) {
        printf("%d\n", x);
    }
}
