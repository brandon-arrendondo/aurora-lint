/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The arm assigns the index past the end after declaring it
 * Expect: count=1
 *
 * The #if arm's index holds 9 by the access, not the 1 it was declared with.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 1;
    i = 9;
#else
    int i = 2;
#endif
    return buf[i];
}
