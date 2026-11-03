/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The assignment after the check writes another object
 *
 * The inner block assigns its own `x`; the checked `x` the division uses
 * is not written between the check and the division.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = read_untrusted();
    if (x != 0) {
        {
            int x = 2;
            x = read_untrusted();
            (void)x;
        }
        return 100 / x;
    }
    return 0;
}
