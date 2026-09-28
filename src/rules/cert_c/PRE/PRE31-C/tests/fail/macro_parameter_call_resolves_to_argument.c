/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: APPLY calls its parameter, so via() calls bump, which writes a
 * static. Calling via() in an argument TWICE evaluates twice is a side
 * effect, as is APPLY(bump, 1) written in the argument itself.
 */

#define APPLY(fn, x) fn(x)
#define TWICE(x) ((x) + (x))

static int counter;

static int bump(int v) {
    counter += v;
    return counter;
}

static int via(void) {
    return APPLY(bump, 1);
}

int use_via(void) {
    return TWICE(via());
}

int use_apply(void) {
    return TWICE(APPLY(bump, 1));
}
