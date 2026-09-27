/*
 * Rule: ERR33-C
 * Status: FAIL - `errno = 0` after the first strtol erases what it left
 * there; the errno test that follows sees only the second call.
 */

#include <errno.h>
#include <stdlib.h>

long f(const char *s, const char *t) {
    long a = strtol(s, NULL, 10);
    errno = 0;
    long b = strtol(t, NULL, 10);
    if (errno) {
        return 0;
    }
    return a + b;
}
