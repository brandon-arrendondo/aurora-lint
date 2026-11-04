/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The step belongs to an inner block's variable
 *
 * The inner `i` is stepped past the end of `buf` but never indexes it. The
 * outer `i` holds 2 where it does.
 */

int fill(void)
{
    int buf[4];
    int i = 2;
    {
        int i = 3;
        i += 5;
        (void)i;
    }
    buf[i] = 0;
    return buf[0];
}
