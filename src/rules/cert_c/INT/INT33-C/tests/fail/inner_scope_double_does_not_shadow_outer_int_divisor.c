/*
 * Rule: INT33-C
 * Source: regression
 * Status: FAIL - `10 / x` divides by the outer int x without a zero check
 *
 * An inner block declares its own `double x`. A function-wide name map keeps
 * one entry per name, and the inner declaration used to answer for the
 * outer `x`, so the division read as floating-point and was skipped. The
 * occurrence's own declaration is the outer int.
 */

int divide(int n) {
    int x = n;
    int r = 10 / x;
    {
        double x = 2.0;
        (void)x;
    }
    return r;
}
