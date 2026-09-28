/*
 * Rule: FLP06-C
 * Source: regression
 * Status: PASS - `floatcount` is an int, so no conversion to float happens
 *
 * The target's name contains `float` and `double`, but its declared type is
 * int: integer arithmetic initializing an integer is not this defect.
 */

int totals(int a, int b)
{
    int floatcount = a + b;
    int doublecheck = a * b;
    return floatcount + doublecheck;
}
