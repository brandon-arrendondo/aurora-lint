/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: bump_t is a function this file defines, which writes counter;
 * a name ending in `_t` is not a type when a declaration says it is a
 * function, so `(bump_t)(1)` calls it, and TWICE calls it twice.
 */

#define TWICE(x) ((x) + (x))

static int counter;

int bump_t(int step) {
    counter += step;
    return counter;
}

int twice_bumped(void) {
    return TWICE((bump_t)(1));  // Expect: here
}
