/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A test clamps the index before the access
 */

int buf[4];

int element(void)
{
    int i = 9;
    if (i > 3)
        i = 3;
    return buf[i];
}
