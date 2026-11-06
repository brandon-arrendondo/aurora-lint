/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A store through a pointer to one of two objects may leave the amount
 *
 * `q` points at `s` or at `t`, so `*q = 40` may write either. The shift
 * may be by 4 or by 40.
 */

int mask(int c)
{
    int s = 4;
    int t = 3;
    int *q = &s;
    if (c)
        q = &t;
    *q = 40;
    return 1 << s;
}
