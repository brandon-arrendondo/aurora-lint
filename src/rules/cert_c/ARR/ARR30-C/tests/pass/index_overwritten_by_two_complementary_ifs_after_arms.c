/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Two later tests of one condition overwrite the index
 *
 * One of them always runs.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#endif
    if (c) {
        i = 0;
    }
    if (!c) {
        i = 1;
    }
    return buf[i];
}
