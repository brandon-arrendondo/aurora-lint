/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: The snprintf result is never compared. The word stderr in a nearby comment is not a check.
 */

#include <stdio.h>

void report(char *buf, size_t size, const char *name) {
    int n;
    /* callers print buf to stderr on failure */
    n = snprintf(buf, size, "name=%s", name);
    puts(buf);
}
