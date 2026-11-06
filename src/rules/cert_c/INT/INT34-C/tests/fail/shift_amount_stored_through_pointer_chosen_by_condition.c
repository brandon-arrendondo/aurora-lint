/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A conditional picks which object the pointer holds
 *
 * `q` points at `s` or at `g`, so `*q = 2` may leave `s` at 40.
 */

int g;

int mask(int c)
{
    int s = 40;
    int *q = c ? &s : &g;
    *q = 2;
    return 1 << s;
}
