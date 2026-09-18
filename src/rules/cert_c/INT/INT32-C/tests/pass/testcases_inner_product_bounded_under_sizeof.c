/*
 * Rule: INT32-C
 * Source: testcases
 * Status: PASS - Should NOT trigger INT32-C violation
 *
 * Counterpart to testcases_inner_signed_product_under_sizeof.c: the inner
 * product's operands are bounded, so it fits int; and a guard on the
 * factors before the allocation is honoured. The outer unsigned product
 * is not this rule's either way (task 1288).
 */
#include <stdlib.h>
#include <string.h>

struct cfg { int rows; int cols; };

void *small_grid(void) {
    int rows = 10;
    int cols = 20;
    return malloc((rows * cols) * sizeof(int));
}

void *guarded_grid(struct cfg *c) {
    if (c->rows <= 0 || c->cols <= 0 || c->rows > INT_MAX / c->cols) {
        return NULL;
    }
    return malloc((c->rows * c->cols) * sizeof(int));
}

void copy_bounded(int *dst, const int *src, unsigned rows, unsigned cols) {
    /* both factors unsigned: the whole computation is INT30-C's */
    memcpy(dst, src, (rows * cols) * sizeof(int));
}
