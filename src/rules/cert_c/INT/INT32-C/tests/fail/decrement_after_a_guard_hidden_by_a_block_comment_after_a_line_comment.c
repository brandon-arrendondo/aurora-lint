/*
 * Rule: INT32-C
 * Source: custom
 * Status: FAIL - Should trigger INT32-C violation
 * Description: The `//` comment here is not continued, so the `/*` on the next
 * line does open a block comment, and it hides the guard and the loop header:
 * the decrement of the parameter is bounded by nothing.
 * Expect: count=1
 */

// No backslash ends this line.
/* A comment that runs over the old loop:
#ifdef HAVE_A
    while (c > 0)
#endif
*/

void count_down(int c)
{
    {
        c--;
    }
}
