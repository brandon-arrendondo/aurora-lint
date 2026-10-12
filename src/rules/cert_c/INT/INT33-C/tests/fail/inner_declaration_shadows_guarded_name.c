/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The guard tests the parameter; the division uses a new
 * variable of the same name
 */

int ratio(int a, int d)
{
    if (d == 0)
        return 0;
    {
        int d = a - 1;
        return a / d;
    }
}
