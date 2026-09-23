/*
 * Rule: INT10-C
 * Source: real-world
 * Status: FAIL - `neg % (rand() % 7 + 1)` takes the sign of `neg`, which can
 *         be negative; a non-negative PRNG DIVISOR proves nothing.
 *
 * The contract range is a fact about the call's own value. It clears a
 * remainder only when the call is the DIVIDEND (C99 6.5.5p6), which is why
 * the PASS twin's cases all have it on the left. This is the one line here
 * that can flag; the PRNG on the right must not suppress it.
 */

#include <stdlib.h>

int f(int neg)
{
    return neg % (rand() % 7 + 1);
}
