/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A stepped pointer no longer points at the amount
 *
 * `q` is moved by `c` before the store, so `*q = 2` need not write `s`.
 */

int mask(int c)
{
    int s = 40;
    int *q = &s;
    q += c;
    *q = 2;
    return 1 << s;
}
