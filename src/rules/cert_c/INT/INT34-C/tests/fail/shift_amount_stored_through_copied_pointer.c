/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - The pointer is a copy of another, not an address taken here
 *
 * `q` copies `r`, which may point at `g`, so `*q = 2` may leave `s` at
 * 40.
 */

int g;

int mask(int c)
{
    int s = 40;
    int *r = c ? &s : &g;
    int *q = r;
    *q = 2;
    return 1 << s;
}
