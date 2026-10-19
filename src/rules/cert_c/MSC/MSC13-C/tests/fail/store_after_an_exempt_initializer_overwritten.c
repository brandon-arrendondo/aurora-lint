/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - `int x = 0;` is exempt, but `x = 1;` after it is a dead store
 */

int f(int c)
{
    int x = 0;
    x = 1;
    x = c;
    return x;
}
