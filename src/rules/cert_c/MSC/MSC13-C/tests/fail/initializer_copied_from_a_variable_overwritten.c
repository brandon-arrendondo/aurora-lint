/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - `int x = y;` copies a value, not a default, and every path overwrites it before a read
 */

int f(int c, int y)
{
    int x = y;
    x = c;
    return x;
}
