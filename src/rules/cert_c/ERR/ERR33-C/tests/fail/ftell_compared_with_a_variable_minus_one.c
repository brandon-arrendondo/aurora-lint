/*
 * Rule: ERR33-C
 * Status: FAIL - `(len) - 1` subtracts from a variable; it is not the cast
 * `(long) -1`, so the ftell result is never compared with -1L.
 */

#include <stdio.h>

int f(FILE *fp, long len) {
    long r = ftell(fp);
    if (r == (len) - 1) {
        return 1;
    }
    return 0;
}
