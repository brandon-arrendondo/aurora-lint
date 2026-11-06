/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - The store through the pointer is one arm of a conditional
 *
 * `*q = 2` runs only when `c` is set, so `s` may still be 40.
 */

int mask(int c)
{
    int s = 40;
    int *q = &s;
    c ? (*q = 2) : 0;
    return 1 << s;
}
