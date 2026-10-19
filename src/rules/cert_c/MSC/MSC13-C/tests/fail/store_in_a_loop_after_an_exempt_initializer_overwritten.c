/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - the loop's `x = c;` is overwritten by `x = 5;` before any read
 */

int f(int c)
{
    int x = 0;
    while (c--) {
        x = c;
    }
    x = 5;
    return x;
}
