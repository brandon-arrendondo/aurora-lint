/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The way that stores 9 returns before the access
 */

int buf[4];

int element(int c)
{
    int i = 1;
    if (c) {
        i = 9;
        return i;
    }
    return buf[i];
}
