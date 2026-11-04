/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The out-of-range value belongs to an inner block's variable
 *
 * The inner `i` holds 9 but never indexes anything. The outer `i` holds 2
 * where it indexes `buf`.
 */

int fill(void)
{
    int buf[4];
    int i = 2;
    {
        int i = 9;
        (void)i;
    }
    buf[i] = 0;
    return buf[0];
}
