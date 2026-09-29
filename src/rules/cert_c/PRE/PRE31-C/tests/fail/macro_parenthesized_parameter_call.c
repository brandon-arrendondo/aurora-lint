/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: APPLYP(bump, 1) expands to (bump)(1), a call of bump, which writes
 * the global g.
 */

#define APPLYP(fn, x) (fn)(x)
#define TWICE(x) ((x) + (x))

int g;

int bump(int x) {
    return g += x;
}

int u1(void) {
    return TWICE(APPLYP(bump, 1));  // VIOLATION
}
