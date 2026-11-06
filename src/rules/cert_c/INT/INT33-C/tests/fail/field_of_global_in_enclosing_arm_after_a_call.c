/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A call may change the global the assert read
 *
 * `freq` is a file-scope object in the arm the function is in. The assert
 * says nothing once `sample` has run, which may store to it.
 */

#ifdef USE_TIMER

struct counter {
    long q;
};

struct counter freq;

long ticks(long c)
{
    DEBUGASSERT(freq.q);
    sample();
    return c / freq.q;
}

#endif
