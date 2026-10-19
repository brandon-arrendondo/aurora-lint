/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - `int x = get();` is a computed value, not MSC13-EX1's default, and every path overwrites it before a read
 */

int get(void);

int f(int c)
{
    int x = get();
    x = c;
    return x;
}
