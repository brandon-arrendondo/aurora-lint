/*
 * Rule: FLP03-C
 * Source: regression
 * Status: FAIL - `a / b` is a floating-point division spelled through a typedef
 *
 * `real` is a typedef of double, so the division by the zero `b` is
 * floating-point even though neither declaration spells `float` or `double`.
 */

typedef double real;

real rate(real a)
{
    real b = 0.0;
    return a / b;
}
