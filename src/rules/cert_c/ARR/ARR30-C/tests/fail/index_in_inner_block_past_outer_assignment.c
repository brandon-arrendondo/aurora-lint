/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The outer variable's assignment is not the inner index's value
 *
 * The inner `i` holds 9 where it indexes `buf`. The later `i = 2` assigns
 * the outer `i`, a different object.
 */

int fill(void)
{
    int buf[4];
    int i;
    {
        int i = 9;
        buf[i] = 1;
    }
    i = 2;
    buf[i] = 0;
    return buf[0];
}
