/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A block's own constant does not vouch for the variable it hides
 * Expect: count=2
 *
 * Each divisor is read from outside and never checked. A block, and a loop,
 * declare a variable of the same name and give it nonzero values; after
 * them the name is the unchecked outer variable again.
 */

int read_untrusted(void);

int ratio_after_block(void)
{
    int x = read_untrusted();
    {
        int x = 4;
        (void)x;
    }
    return 100 / x; /* Expect: here */
}

int ratio_after_loop(void)
{
    int i = read_untrusted();
    for (int i = 1; i < 5; i++)
        (void)i;
    return 100 / i; /* Expect: here */
}
