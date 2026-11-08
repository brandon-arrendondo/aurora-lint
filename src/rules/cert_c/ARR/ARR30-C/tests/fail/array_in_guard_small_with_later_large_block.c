/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The guarded file-scope array has four elements
 * Expect: count=1
 *
 * The access names the file-scope array inside the conditional, not the
 * larger local of the block after it.
 */

#ifndef BUF_H
int buf[4];

int element(void)
{
    int r = buf[7];
    {
        int buf[8];
        buf[0] = 1;
        r += buf[0];
    }
    return r;
}
#endif
