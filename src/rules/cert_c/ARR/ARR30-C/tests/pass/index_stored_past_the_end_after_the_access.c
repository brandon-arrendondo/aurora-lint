/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The store past the end comes after the access
 *
 * The access reads index 1. The 9 is stored after it, and no loop takes
 * the code back to the access.
 */

int buf[4];

int element(void)
{
    int i = 1;
    int r = buf[i];
    i = 9;
    return r + i;
}
