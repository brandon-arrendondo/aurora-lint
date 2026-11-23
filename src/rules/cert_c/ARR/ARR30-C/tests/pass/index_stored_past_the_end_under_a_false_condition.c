/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The store past the end never runs
 *
 * The value range at the access holds only 1.
 */

int buf[4];

int element(void)
{
    int i = 1;
    if (0)
        i = 9;
    return buf[i];
}
