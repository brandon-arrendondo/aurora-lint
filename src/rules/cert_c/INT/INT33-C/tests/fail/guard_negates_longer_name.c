/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The guard negates xy, not x
 *
 * `!xy` begins with the text `!x`, but it says nothing about x.
 */

int xy;

int divide(int a, int x)
{
    if (!xy)
        return 0;
    return a / x;
}
