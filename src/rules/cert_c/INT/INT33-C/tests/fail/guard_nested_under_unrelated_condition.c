/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero guard runs only when v is set
 *
 * When v is zero the inner test never runs, and d reaches the division
 * unchecked. A guard counts only when it is on every path to the division.
 */

int divide(int a, int d, int v)
{
    if (v) {
        if (d == 0)
            return 0;
    }
    return a / d;
}
