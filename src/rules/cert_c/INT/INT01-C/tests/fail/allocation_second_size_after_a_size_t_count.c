/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int element size after a size_t count
 *
 * calloc takes two sizes. n is a size_t, but len, the element size after
 * it, is held in an int.
 */
#include <stdlib.h>

int elem_width(void);

void *make_cells(size_t n) {
    int len = elem_width();
    return calloc(n, len);
}
