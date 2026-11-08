/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The arm brings the index back in bounds
 *
 * The #if arm's index holds 1 by the access, not the 9 it was declared with.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 9;
    i = 1;
#else
    int i = 2;
#endif
    return buf[i];
}
