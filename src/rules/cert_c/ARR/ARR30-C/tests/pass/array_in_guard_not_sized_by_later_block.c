/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The guarded file-scope array is the one indexed
 *
 * The eight-element array is at file scope inside a conditional, and the
 * four-element one is a local of a block after the access, which the
 * access does not name.
 */

#ifndef BUF_H
int buf[8];

int element(void)
{
    int i = 7;
    int r = buf[i];
    {
        int buf[4];
        buf[0] = 1;
        r += buf[0];
    }
    return r;
}
#endif
