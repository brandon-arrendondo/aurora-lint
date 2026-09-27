/*
 * Rule: ERR33-C
 * Status: FAIL - the second strtol overwrites the end pointer before it is
 * tested, so the test says nothing about the first call.
 */

#include <stdlib.h>

long f(const char *s, const char *t) {
    char *end;
    long a = strtol(s, &end, 10);
    long b = strtol(t, &end, 10);
    if (end == t) {
        return 0;
    }
    return a + b;
}
