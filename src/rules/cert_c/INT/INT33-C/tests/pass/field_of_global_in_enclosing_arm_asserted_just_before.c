/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * `freq` is a file-scope object in the arm the function is in, and no call
 * separates the assert from the division, so nothing can change it between
 * the two. The strict policy reads the release configuration, where NDEBUG
 * strips the assert and the division is unchecked.
 */

#ifdef USE_TIMER

struct counter {
    long q;
};

struct counter freq;

long ticks(long c)
{
    DEBUGASSERT(freq.q);
    return c / freq.q;
}

#endif
