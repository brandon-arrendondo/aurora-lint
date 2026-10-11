/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The divisor is reassigned between the guard and the division
 */

int divide(int a, int d, int z)
{
    if (d == 0)
        return 0;
    d = z;
    return a / d;
}
