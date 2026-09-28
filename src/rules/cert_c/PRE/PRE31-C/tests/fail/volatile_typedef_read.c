/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: reg_t is a volatile-qualified typedef, so *R reads a volatile
 * object: rd() has a side effect, and so does *R in the argument itself.
 */

#define TWICE(x) ((x) + (x))

typedef volatile unsigned reg_t;

static reg_t *R;

static unsigned rd(void) {
    return *R;
}

unsigned use_rd(void) {
    return TWICE(rd());
}

unsigned direct_read(void) {
    return TWICE(*R);
}
