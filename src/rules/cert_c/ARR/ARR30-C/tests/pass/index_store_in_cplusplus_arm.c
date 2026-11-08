/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The arm storing past the end is C++ only
 *
 * A C build never compiles it.
 */

int buf[4];
int c;

int element(void)
{
    int i;
#ifdef __cplusplus
    i = 9;
#else
    i = 1;
#endif
    return buf[i];
}
