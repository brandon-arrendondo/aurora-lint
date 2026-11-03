/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The pointer may still hold the divisor's address
 *
 * Which object a pointer holds is not tracked statement by statement: once
 * `q` has held `&x`, a store through it is taken to reach `x`, even where
 * a later assignment pointed it elsewhere. The finding is conservative:
 * here `q` points at `y` when the store runs, so `x` is still 1.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = 1;
    int y = 1;
    int *q = &x;
    q = &y;
    *q = read_untrusted();
    return 100 / x;
}
