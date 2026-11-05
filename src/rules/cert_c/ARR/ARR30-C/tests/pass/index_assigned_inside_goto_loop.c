/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Each pass of the goto loop assigns the index before the access
 *
 * The store through `q` follows the access, but the `goto` goes back to
 * before `i = 2`, so every pass indexes with 2.
 */

int read_untrusted(void);

int buf[4];

int sum(int count)
{
    int i;
    int r = 0;
    int *q = &i;
again:
    i = 2;
    r += buf[i];
    *q = read_untrusted();
    if (--count)
        goto again;
    return r;
}
