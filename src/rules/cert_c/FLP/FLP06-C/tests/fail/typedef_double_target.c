/*
 * Rule: FLP06-C
 * Source: regression
 * Status: FAIL - `a / b` is integer division, converted to double afterwards
 *
 * `real` is a typedef of double, so the target is floating-point even though
 * its declaration spells neither `float` nor `double`.
 */

typedef double real;

real share(int a, int b)
{
    real r = a / b;
    return r;
}
