/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A store later in a goto loop reaches the next pass's shift
 *
 * The `goto` back to `again` makes a loop. The store through `q` follows
 * the shift in it, so every pass after the first shifts by the unchecked
 * value.
 */

int read_untrusted(void);

int masks(int count)
{
    int s = 3;
    int r = 0;
    int *q = &s;
again:
    r |= 1 << s;
    *q = read_untrusted();
    if (--count)
        goto again;
    return r;
}
