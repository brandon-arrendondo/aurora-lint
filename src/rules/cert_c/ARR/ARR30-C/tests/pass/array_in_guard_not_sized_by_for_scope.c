/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A for-scope array is not the guarded array
 *
 * The four-element array is declared by the `for`, and its scope ends with
 * the loop. The access after the loop's own declaration point but outside
 * it names the eight-element array.
 */

#ifndef BUF_H
int buf[8];

int element(void)
{
    int r = buf[7];
    for (int buf[4], k = 0; k < 1; k++) {
        buf[k] = 0;
    }
    return r;
}
#endif
