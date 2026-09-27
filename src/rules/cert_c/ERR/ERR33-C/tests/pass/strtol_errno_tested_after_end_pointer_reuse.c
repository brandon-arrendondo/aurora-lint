/*
 * Rule: ERR33-C
 * Status: PASS - a second strtol that reuses the end pointer does not clear
 * errno, so an ERANGE from the first call is still seen by the errno test.
 */

#include <errno.h>
#include <stdlib.h>

long f(const char *s) {
    char *e;
    errno = 0;
    long a = strtol(s, &e, 10);
    long b = strtol(e, &e, 10);
    if (errno) {
        return -1;
    }
    return a + b;
}
