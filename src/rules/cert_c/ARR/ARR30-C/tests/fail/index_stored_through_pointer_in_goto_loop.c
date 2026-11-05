/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A store later in a goto loop reaches the next pass's access
 * Expect: count=1
 *
 * The `goto` back to `again` makes a loop. The store through `q` follows
 * the access in it, so every pass after the first indexes with the
 * unchecked value.
 */

int read_untrusted(void);

int buf[4];

int sum(int count)
{
    int i = 2;
    int r = 0;
    int *q = &i;
again:
    r += buf[i]; /* Expect: here */
    *q = read_untrusted();
    if (--count)
        goto again;
    return r;
}
