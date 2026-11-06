/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - The pointer is repointed through parentheses before the store
 *
 * `(q) = &t` points `q` at `t`, so `*q = 2` leaves `s` at 40.
 */

int t;

int mask(void)
{
    int s = 40;
    int *q = &s;
    (q) = &t;
    *q = 2;
    return 1 << s;
}
