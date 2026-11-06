/*
 * Rule: INT32-C
 * Source: custom
 * Status: PASS - Should NOT trigger INT32-C violation
 * Description: A guard falls between a loop header and its braced body, after
 * a `//` comment a `\` continues onto the next line. That line is still the
 * comment, so the `/*` on it opens nothing, the guard is found and blanked,
 * the header rejoins its body, and the decrement is read under `c > 0`.
 */

// The next line is part of this comment: \
/* not a block comment

void count_down(int c)
{
#ifdef HAVE_A
    while (c > 0)
#endif
    {
        c--;
    }
}
