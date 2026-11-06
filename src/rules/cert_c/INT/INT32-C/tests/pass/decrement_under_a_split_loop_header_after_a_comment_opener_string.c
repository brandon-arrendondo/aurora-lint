/*
 * Rule: INT32-C
 * Source: custom
 * Status: PASS - Should NOT trigger INT32-C violation
 * Description: A guard falls between a loop header and its braced body,
 * after strings that hold a comment opener and a comment closer. Inside a
 * literal those open and close no comment, so the guard is still found and
 * blanked, the header rejoins its body, and the decrement is read under
 * `c > 0`.
 */

static const char *accept = "Accept: */*";
static const char *pattern = "dir/*";

void count_down(int c)
{
#ifdef HAVE_A
    while (c > 0)
#endif
    {
        c--;
    }
}
