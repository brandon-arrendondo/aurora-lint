/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 *
 * The two-stage size computation: `(a * b) * sizeof(T)` performs `a * b`
 * in int before anything is converted to size_t. The outer product is
 * unsigned and INT30-C's; the inner one is signed and can
 * overflow with the outer never involved. The operands here
 * are struct fields and call results -- shapes the operator walker's
 * provenance gate declines -- so only the size-argument sink sees them.
 */
#include <stdlib.h>
#include <string.h>

struct cfg { int rows; int cols; };
int read_int(void);

void *grid_fields(struct cfg *c) {
    /* VIOLATION: c->rows * c->cols overflows int before the sizeof multiply */
    return malloc((c->rows * c->cols) * sizeof(int));
}

void *grid_calls(void) {
    int rows = read_int();
    int cols = read_int();
    /* VIOLATION */
    return malloc((rows * cols) * sizeof(int));
}

void copy_grid(int *dst, const int *src, struct cfg *c) {
    /* VIOLATION: same shape at a memcpy size argument */
    memcpy(dst, src, (c->rows * c->cols) * sizeof(int));
}
