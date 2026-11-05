/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An #elif arm declares the index past the end
 * Expect: count=1
 *
 * The first arm declares the index in bounds and the #elif arm past
 * the end. Either arm may be the one built, so the access is reported
 * with the #elif arm's index.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 1;
#elif defined(B)
    int i = 7;
#endif
    return buf[i]; /* Expect: here */
}
