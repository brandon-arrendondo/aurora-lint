/*
 * Rule: ERR33-C
 * Status: PASS - errno cleared before the call and tested after it.
 */

#include <errno.h>
#include <stdlib.h>

long f(const char *s) {
    errno = 0;
    long a = strtol(s, NULL, 10);
    if (errno) {
        return 0;
    }
    return a;
}
