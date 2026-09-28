/*
 * Rule: FLP03-C
 * Source: regression
 * Status: PASS - `(int)d / n` divides two ints
 *
 * The double is converted to int before the division, so the division is an
 * integer one; that the cast's operand is a double does not make it a
 * floating-point division.
 */

int buckets(double x)
{
    double d = x;
    int n = 0;
    return (int)d / n;
}
