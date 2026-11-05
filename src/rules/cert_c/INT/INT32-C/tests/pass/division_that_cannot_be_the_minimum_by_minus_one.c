/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: PASS - A division whose dividend is not the minimum, or whose divisor is not -1, cannot overflow
 *
 * The only signed division that overflows is the type's minimum divided
 * by -1. `INT_MAX / b` never divides the minimum, and `INT_MIN / a` under
 * `a > 0` never divides by -1, whether or not the quotient is then
 * compared, as the precondition checks for a product do.
 */

#include <limits.h>

int product_fits(int a, int b)
{
    if (b != 0 && a > INT_MAX / b)
        return 0;
    if (a > 0) {
        if (b < INT_MIN / a)
            return 0;
    }
    return 1;
}

int quotient(int a, int b)
{
    if (b <= 0)
        return 0;
    return a / b;
}
