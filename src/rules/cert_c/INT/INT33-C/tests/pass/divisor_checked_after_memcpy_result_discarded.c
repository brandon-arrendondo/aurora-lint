/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - memcpy writes the divisor before the check
 *
 * The copy into `x` happens during the call, and its returned pointer is
 * discarded, so nothing can write `x` after the check.
 */

#include <string.h>

int ratio(int y)
{
    int x = 1;
    memcpy(&x, &y, sizeof x);
    if (x == 0)
        return 0;
    return 100 / x;
}
