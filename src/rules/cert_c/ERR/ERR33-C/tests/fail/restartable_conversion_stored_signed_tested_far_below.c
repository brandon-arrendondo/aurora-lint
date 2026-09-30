/*
 * Rule: ERR33-C
 * Status: FAIL - mbrlen() returns (size_t)-1 on an encoding error, which
 * an int holds as -1. An ordering at -1000 separates nothing the call
 * returns.
 */

#include <wchar.h>

int width(const char *s, mbstate_t *st) {
    long n = mbrlen(s, 4, st);
    if (n <= -1000) {
        return -1;
    }
    return (int)n;
}
