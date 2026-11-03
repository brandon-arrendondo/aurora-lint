/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - memcpy hands back the pointer it was given
 *
 * `memcpy` returns its destination, so `q` points at `s` and the store
 * through it replaces the 3 the shift amount was given.
 */

#include <string.h>

int mask(int v)
{
    int s = 3;
    int *q = memcpy(&s, &s, sizeof s);
    *q = v;
    return 1 << s;
}
