/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The divisor is overwritten through a pointer after the check
 *
 * The check saw a non-zero `x`, but the store through `q` between the check
 * and the division may make it zero again.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = 1;
    int *q = &x;
    if (x == 0)
        return 0;
    *q = read_untrusted();
    return 100 / x;
}
