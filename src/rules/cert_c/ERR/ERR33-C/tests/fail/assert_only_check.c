/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: The only NULL test is inside assert(), which NDEBUG removes, so no build-independent check guards the result.
 */

#include <assert.h>
#include <stdlib.h>

int *make(size_t n) {
    int *p = malloc(n * sizeof *p);
    assert(p != NULL);
    p[0] = 0;
    return p;
}
