/*
 * Rule: FLP02-C
 * Source: regression
 * Status: FAIL - `a == b` compares two doubles spelled through a typedef
 *
 * `real` is a typedef of double, so both operands are floating-point even
 * though neither declaration spells `float` or `double`.
 */

typedef double real;

int same_reading(real a, real b)
{
    return a == b;
}
