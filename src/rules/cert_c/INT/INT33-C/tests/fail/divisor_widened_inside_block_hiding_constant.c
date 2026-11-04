/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The block's own variable holds a value read from outside
 * Expect: count=3
 *
 * An outer constant of the same name does not vouch for a block's own
 * variable: each division here reads a variable that may be zero.
 */

int read_untrusted(void);

int inner_ratio(void)
{
    int x = 1;
    {
        int x = 2;
        x = read_untrusted();
        return 100 / x; /* Expect: here */
    }
}

int innermost_ratio(void)
{
    int x = 1;
    {
        int x = 3;
        {
            int x = read_untrusted();
            (void)(100 / x); /* Expect: here */
        }
        (void)(100 / x);
    }
    return 100 / x;
}

int loop_ratio(void)
{
    int i = 2;
    for (int i = read_untrusted(); i < 10; i++) {
        (void)(100 / i); /* Expect: here */
    }
    return 100 / i;
}
