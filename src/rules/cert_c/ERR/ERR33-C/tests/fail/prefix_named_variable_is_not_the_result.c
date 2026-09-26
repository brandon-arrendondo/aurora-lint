/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: FAIL - Should trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: FAIL
 * Reason: The only test is of 'sz', a different variable whose name merely starts with 's'. '!sz' does not test 's', so the malloc result is used unchecked.
 */

#include <stdlib.h>
#include <string.h>

void copy(const char *in, size_t sz) {
    char *s = malloc(sz + 1);
    if (!sz) {
        return;
    }
    memcpy(s, in, sz);
    s[sz] = '\0';
    free(s);
}
