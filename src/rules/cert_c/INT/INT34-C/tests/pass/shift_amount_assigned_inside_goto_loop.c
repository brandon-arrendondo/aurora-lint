/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - Each pass of the goto loop assigns the amount before the shift
 *
 * The store through `q` follows the shift, but the `goto` goes back to
 * before `s = 3`, so every pass shifts by 3.
 */

int read_untrusted(void);

int masks(int count)
{
    int s;
    int r = 0;
    int *q = &s;
again:
    s = 3;
    r |= 1 << s;
    *q = read_untrusted();
    if (--count)
        goto again;
    return r;
}
