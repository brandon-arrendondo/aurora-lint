/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A callee is handed a pointer to the divisor after the check
 *
 * `refill` may store anything through `q`, which points at `x`.
 */

int read_untrusted(void);
void refill(int *out);

int ratio(void)
{
    int x = 1;
    int *q = &x;
    *q = read_untrusted();
    if (x == 0)
        return 0;
    refill(q);
    return 100 / x;
}
