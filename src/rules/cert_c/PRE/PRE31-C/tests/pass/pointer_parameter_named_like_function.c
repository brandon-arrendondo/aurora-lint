/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: next() in f is a call through the parameter next, not the
 * function next() defined above, whatever its effects: a call through a
 * pointer names no body, so only the strict preset reports it.
 */

#define TWICE(x) ((x) + (x))

static int counter;

int next(void) {
    return ++counter;
}

int f(int (*next)(void)) {
    return TWICE(next());
}
