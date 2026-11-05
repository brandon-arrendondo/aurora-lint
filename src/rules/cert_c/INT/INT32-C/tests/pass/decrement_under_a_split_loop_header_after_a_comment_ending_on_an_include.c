/*
 * Rule: INT32-C
 * Source: custom
 * Status: PASS - Should NOT trigger INT32-C violation
 * Description: A guard falls between a loop header and its braced body,
 * after a comment whose last line is an `#include` with the `*/` on it.
 * Inside a comment a `#` line is comment text, not a directive, so the
 * `*/` on it still closes the comment; the guard is found and blanked, the
 * header rejoins its body, and the decrement is read under `c > 0`.
 */

/* Usage:
#include "counter.h" */

void count_down(int c)
{
#ifdef HAVE_A
    while (c > 0)
#endif
    {
        c--;
    }
}
