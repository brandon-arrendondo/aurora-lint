/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The check reads the divisor after the store through a
 * pointer to it
 *
 * Nothing between the check and the division writes through `q` or hands
 * it to a call, so the value the check saw is the value divided by. Taking
 * the address alone does not make the check stale.
 */

int read_untrusted(void);
void log_event(void);

int ratio(void)
{
    int x = 1;
    int *q = &x;
    *q = read_untrusted();
    if (x != 0)
        return 100 / x;
    return 0;
}

int ratio_after_early_return(void)
{
    int x = 1;
    int *q = &x;
    *q = read_untrusted();
    if (x == 0)
        return 0;
    log_event();
    return 100 / x;
}
