/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - The store writes the inner block's own variable
 *
 * The inner `s` is a separate object: storing through a pointer to it
 * leaves the outer `s` holding 3.
 */

int read_untrusted(void);

int mask(void)
{
    int s = 3;
    {
        int s = 0;
        int *q = &s;
        *q = read_untrusted();
        (void)s;
    }
    return 1 << s;
}
