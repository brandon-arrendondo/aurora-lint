/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The guard tests max, not x
 *
 * `max != 0` contains the text `x != 0`, but it says nothing about x.
 */

int max;

int divide(int a, int x)
{
    if (max != 0)
        return a / x;
    return 0;
}
