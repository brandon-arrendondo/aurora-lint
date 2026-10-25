/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int member as the element size after a size_t count
 *
 * calloc takes two sizes. n is a size_t, but the element size after it is
 * an int member.
 */
#include <stdlib.h>

struct table { int elem_len; };

void *make_rows(size_t n, struct table *s) {
    return calloc(n, s->elem_len);
}
