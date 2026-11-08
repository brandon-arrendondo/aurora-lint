/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every arm replaces the initial value
 *
 * The chain ends in #else and both arms assign, so no build keeps the 9.
 */

int buf[4];

int element(void)
{
    int i = 9;
#if defined(A)
    i = 1;
#else
    i = 2;
#endif
    return buf[i];
}
