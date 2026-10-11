/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A non-null pointer may point at zero
 *
 * `if (p)` tests the pointer. The divisor is the int it points at.
 */

int divide(int a, const int *p)
{
    if (p)
        return a / *p;
    return 0;
}
