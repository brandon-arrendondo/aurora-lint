/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The checked divisor is overwritten through a pointer
 *
 * The inner block declares its own `x`, which the store does not touch;
 * `q` holds the outer `x`'s address, and the store through it after the
 * check replaces the value the check saw.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = read_untrusted();
    int *q = &x;
    if (x != 0) {
        {
            int x = 0;
            (void)x;
        }
        *q = read_untrusted();
        return 100 / x;
    }
    return 0;
}
