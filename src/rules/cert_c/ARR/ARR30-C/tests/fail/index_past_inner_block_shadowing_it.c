/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An inner block's assignment is not the outer index's value
 *
 * `i = 2` assigns the inner block's own `i`. The outer `i` still holds 7
 * where it indexes `buf`.
 */

int fill(void)
{
    int buf[4];
    int i = 7;
    {
        int i = 2;
        buf[i] = 1;
    }
    buf[i] = 0;
    return buf[0];
}
