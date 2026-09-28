/*
 * Rule: FLP02-C
 * Source: regression
 * Status: PASS - `(int)a == (int)b` compares two ints
 *
 * Each operand is cast to int before the comparison, so no floating-point
 * value is compared. The casts' operands being double does not make the
 * comparison a floating-point one.
 */

int same_whole_part(double a, double b)
{
    return (int)a == (int)b;
}
