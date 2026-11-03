/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The store after the check writes another object
 *
 * The inner block's `x` is a separate object from the checked `x`: taking
 * its address and storing through the pointer leave the outer `x` as the
 * check found it.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = read_untrusted();
    if (x != 0) {
        {
            int x = 2;
            int *q = &x;
            *q = read_untrusted();
            (void)x;
        }
        return 100 / x;
    }
    return 0;
}
