/*
 * Rule: FLP06-C
 * Source: regression
 * Status: PASS - `r1 * r2` multiplies two doubles
 *
 * `real` is a typedef of double, so the arithmetic is already floating-point;
 * nothing is computed in an integer type first.
 */

typedef double real;

double area(real r1, real r2)
{
    double d = r1 * r2;
    return d;
}
