/*
 * Rule: DCL15-C
 * Source: custom
 * Status: FAIL - Should trigger DCL15-C violation
 * Description: An `#ifdef` no `#endif` closes, as in a truncated file. The
 * `#endif` line that follows it is inside a string a `\` continues, so it
 * closes nothing. The conditional's directive is blanked and its code kept:
 * helper, which nothing outside the file calls, has external linkage.
 * Expect: count=1
 */

#ifdef HAVE_EXTRA
static const char note[] = "text\
#endif\
";

int helper(int x)
{
    return x + note[0];
}
