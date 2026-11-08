/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every arm declares the index, so the outer one is never used
 *
 * The chain ends in #else and each arm declares the index, so no build
 * reaches the outer 9.
 */

int buf[4];

int element(void)
{
    int i = 9;
    {
#if defined(A)
        int i = 1;
#else
        int i = 2;
#endif
        return buf[i];
    }
}
