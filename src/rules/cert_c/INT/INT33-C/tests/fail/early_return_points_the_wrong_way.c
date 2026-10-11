/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The early return leaves when x is non-zero
 *
 * Falling past `if (x != 0) return 1;` means x is zero, so the division
 * after it always divides by zero.
 */

int divide(int a, int x)
{
    if (x != 0)
        return 1;
    return a / x;
}
