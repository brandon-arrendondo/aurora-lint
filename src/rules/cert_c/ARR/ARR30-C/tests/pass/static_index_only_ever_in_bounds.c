/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A static index that only ever holds in-bounds values
 *
 * `i` starts at 1 and is only ever set to 3, so whichever call reads it,
 * `buf[i]` stays inside `buf[5]`.
 */

int f(int c)
{
    int buf[5] = {0};
    static int i = 1;
    int r = buf[i];
    if (c)
        i = 3;
    return r;
}
