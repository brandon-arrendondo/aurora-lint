/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The division is in the branch where the divisor is zero
 *
 * A zero test is a guard only on the side where it excludes zero. Here the
 * division runs exactly when x is zero.
 */

int divide(int a, int x)
{
    if (x == 0) {
        return a / x;
    }
    return 0;
}
