/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A goto carries a store past the end to the access it jumps to
 * Expect: count=3
 *
 * `retry` and `again` jump back above the access after `i` becomes 9, so
 * the next read is `buf[9]` of `buf[5]`. In `forward`, the goto skips the
 * store of 2 and lands on the access with `i` still 9.
 */

int retry_loop(int c)
{
    int buf[5] = {0};
    int r = 0;
    int i = 1;
retry:
    r += buf[i]; /* Expect: here */
    if (c-- > 0) {
        i = 9;
        goto retry;
    }
    return r;
}

int again_loop(int c)
{
    int buf[5] = {0};
    int r = 0;
    int i = 1;
again:
    r += buf[i]; /* Expect: here */
    i = 9;
    if (c--)
        goto again;
    return r;
}

int forward(int c)
{
    int buf[5] = {0};
    int i = 0;
    if (c) {
        i = 9;
        goto done;
    }
    i = 2;
done:
    return buf[i]; /* Expect: here */
}
