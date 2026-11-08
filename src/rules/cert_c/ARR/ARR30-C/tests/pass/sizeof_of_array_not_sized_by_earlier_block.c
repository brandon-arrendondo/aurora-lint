/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - `sizeof(buf) - 1` is this `buf`, not an earlier block's
 *
 * The first `buf[N]` in the file is in a block that has ended. The operand
 * of `sizeof` names the eight-element array, so the index is 7.
 */

int element(void)
{
    {
        char buf[16];
        buf[0] = 1;
    }
    char buf[8];
    return buf[sizeof(buf) - 1];
}
