/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The #else arm after an #elif declares the index past the end
 * Expect: count=1
 *
 * Of the three arms only the last declares the index past the end of
 * the buffer. Any of them may be the one built, so the access is
 * reported with that arm's index.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 1;
#elif defined(B)
    int i = 2;
#else
    int i = 7;
#endif
    return buf[i]; /* Expect: here */
}
