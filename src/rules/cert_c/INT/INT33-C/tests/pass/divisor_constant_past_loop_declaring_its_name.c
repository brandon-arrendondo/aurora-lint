/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - A loop's own counter does not replace the variable it hides
 *
 * The `for` declares its own `i` and counts it down to zero. After the loop
 * `i` is the outer variable again, still 2. The parameter `p`, which every
 * caller passes nonzero, is hidden by a block's zero the same way.
 */

int after_loop(void)
{
    int i = 2;
    for (int i = 3; i > 0; i--) {
        (void)i;
    }
    return 100 / i;
}

static int after_hiding_block(int p)
{
    {
        int p = 0;
        (void)p;
    }
    return 100 / p;
}

int callers(void)
{
    return after_hiding_block(3) + after_hiding_block(4);
}
