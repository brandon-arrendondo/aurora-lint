/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - MSC13-EX1 covers the declaration's initializer only; `x = 0;` after it is an assignment like any other
 */

int f(int c)
{
    int x;
    x = 0;
    x = c;
    return x;
}
