/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A repeated condition pairs the access with its arm
 *
 * The access compiles only with A undefined, where the index is 1.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 9;
#else
    int i = 1;
#endif
#if defined(A)
    return i;
#else
    return buf[i];
#endif
}
