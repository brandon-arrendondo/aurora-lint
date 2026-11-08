/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A nested arm past the end
 * Expect: count=1
 *
 * The inner #else arm's store is a way through the outer #if arm.
 */

int buf[4];

int element(void)
{
    int i = 1;
#if defined(A)
#if defined(B)
    i = 2;
#else
    i = 9;
#endif
#endif
    return buf[i];
}
