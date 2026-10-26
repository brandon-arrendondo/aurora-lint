/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: `unsigned long` is one argument, so the call is the second
 * argument, which the cast macro evaluates exactly once.
 */

#define cast(t, exp) ((t)(exp))

static int counter;

static int next(void) {
    return ++counter;
}

unsigned long c(void) {
    return cast(unsigned long, next());
}
