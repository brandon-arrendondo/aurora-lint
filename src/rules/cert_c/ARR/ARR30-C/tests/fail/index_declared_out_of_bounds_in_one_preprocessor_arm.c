/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - One preprocessor arm declares the index past the end
 * Expect: count=1
 *
 * Each arm of the conditional declares the index with a different
 * constant. The arms are alternatives, not a sequence, so the last
 * one written is not the value the index holds: the other arm's 9 is
 * past the end of the buffer whenever BIG is defined.
 */

int buf[3];

int element(void)
{
#if defined(BIG)
    int i = 9;
#else
    int i = 2;
#endif
    return buf[i]; /* Expect: here */
}
