/*
 * Rule: FLP02-C
 * Source: regression
 * Status: PASS - `x == y` in same_count compares two ints
 *
 * Another function declares its own `double x` and `double y`. A name is not a variable:
 * the `x` compared here is same_count's int parameter.
 */

double scale(double x, double y)
{
    return x * y;
}

int same_count(int x, int y)
{
    return x == y;
}
