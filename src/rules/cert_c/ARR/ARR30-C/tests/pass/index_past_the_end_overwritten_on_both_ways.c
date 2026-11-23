/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Both branches overwrite the initial index
 *
 * The 9 the index starts with does not survive either branch.
 */

int buf[4];

int element(int c)
{
    int i = 9;
    if (c)
        i = 2;
    else
        i = 3;
    return buf[i];
}
