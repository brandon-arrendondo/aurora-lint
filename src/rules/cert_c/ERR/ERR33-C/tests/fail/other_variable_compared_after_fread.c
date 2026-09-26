/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: fread's count is stored in 'n', but only 'len' is compared. 'len == 0' is not a test of 'n'.
 */

#include <stdio.h>

size_t load(FILE *f, char *buf, size_t len) {
    size_t n = fread(buf, 1, len, f);
    if (len == 0) {
        return 0;
    }
    buf[len - 1] = '\0';
    return len;
}
