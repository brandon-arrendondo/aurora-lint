/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - Signed arithmetic overflows inside a comparison too
 * Expect: count=5
 *
 * Each operand is a caller's argument, never bounded. Comparing the result
 * does not keep the arithmetic from overflowing first: `a + b > lim`
 * overflows before it compares, and `i + 1 <= i`, written to detect a
 * wrap, is itself the overflow it means to detect.
 */

int sum_exceeds(int a, int b, int lim)
{
    return a + b > lim; /* Expect: here */
}

int next_wraps(int i)
{
    if (i + 1 <= i) /* Expect: here */
        return 1;
    return 0;
}

int difference_negative(int a, int b)
{
    return a - b < 0; /* Expect: here */
}

int product_exceeds(int a, int b, int lim)
{
    return a * b > lim; /* Expect: here */
}

int quotient_positive(int a, int b)
{
    if (b == 0)
        return 0;
    return a / b > 0; /* Expect: here */
}
