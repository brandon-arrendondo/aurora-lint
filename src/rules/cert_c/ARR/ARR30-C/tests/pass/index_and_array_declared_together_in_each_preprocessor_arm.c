/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Each preprocessor arm declares its own array and index
 *
 * One arm declares an eight-element array with index 7 and the other a
 * four-element array with index 3. Each build pairs its index with its
 * own array, so no build indexes past the end.
 */

int element(void)
{
#if defined(A)
    int buf[8];
    int i = 7;
#else
    int buf[4];
    int i = 3;
#endif
    buf[0] = 0;
    return buf[i];
}
