/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - Plain stores in both arms, the first past the end
 * Expect: count=1
 *
 * The last store written is the #else arm's, which is not in sequence with
 * the #if arm's.
 */

int buf[4];

int element(void)
{
    int i;
#if defined(A)
    i = 9;
#else
    i = 1;
#endif
    return buf[i];
}
