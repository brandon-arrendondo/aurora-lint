/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: The NULL test is of an inner 'p' that shadows the stored one; the outer malloc result is never tested.
 */

#include <stdlib.h>

void fill(size_t n) {
    char *p = malloc(n);
    {
        char *p = "fallback";
        if (p == NULL) {
            return;
        }
    }
    p[0] = 'x';
    free(p);
}
