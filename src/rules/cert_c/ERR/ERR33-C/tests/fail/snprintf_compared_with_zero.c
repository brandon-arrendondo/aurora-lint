/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: snprintf signals an error with a negative result and truncation with a result >= size; '== 0' detects neither.
 */

#include <stdio.h>

void fmt(char *buf, size_t size, int v) {
    int n = snprintf(buf, size, "%d", v);
    if (n == 0) {
        return;
    }
    puts(buf);
}
