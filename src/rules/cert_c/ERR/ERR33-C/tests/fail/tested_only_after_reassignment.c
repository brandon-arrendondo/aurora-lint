/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: The first fopen result is overwritten before the only NULL test, which tests the second result.
 */

#include <stdio.h>

void open_both(const char *a, const char *b) {
    FILE *f = fopen(a, "r");
    f = fopen(b, "r");
    if (f == NULL) {
        return;
    }
    fclose(f);
}
