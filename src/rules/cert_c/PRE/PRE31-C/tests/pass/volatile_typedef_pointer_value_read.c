/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: R points to a volatile-qualified typedef, but comparing R reads
 * only the pointer, which is not volatile.
 */

#define TWICE(x) ((x) + (x))

typedef volatile unsigned reg_t;

static reg_t *R;

static int is_mapped(void) {
    return R != 0;
}

int use_is_mapped(void) {
    return TWICE(is_mapped());
}
