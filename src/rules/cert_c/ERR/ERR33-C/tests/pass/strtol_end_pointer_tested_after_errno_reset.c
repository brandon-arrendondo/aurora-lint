/*
 * Rule: ERR33-C
 * Status: PASS - clearing errno does not touch the end pointer, which is
 * tested next.
 */

#include <errno.h>
#include <stdlib.h>

long f(const char *s) {
    char *end;
    long v = strtol(s, &end, 10);
    errno = 0;
    if (end == s) {
        return -1;
    }
    return v;
}
