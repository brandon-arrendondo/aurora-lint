/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The arm storing past the end is #if 0
 *
 * No configuration compiles it.
 */

int buf[4];
int c;

int element(void)
{
    int i;
#if 0
    i = 9;
#else
    i = 1;
#endif
    return buf[i];
}
