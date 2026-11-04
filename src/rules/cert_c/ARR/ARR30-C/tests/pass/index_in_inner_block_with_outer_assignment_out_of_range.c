/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The out-of-range value belongs to the outer variable
 *
 * The inner `i` holds 2 where it indexes `buf`. The later `i = 9` assigns
 * the outer `i`, which never indexes anything.
 */

int fill(void)
{
    int buf[4];
    int i;
    {
        int i = 2;
        buf[i] = 1;
    }
    i = 9;
    (void)i;
    return buf[0];
}
