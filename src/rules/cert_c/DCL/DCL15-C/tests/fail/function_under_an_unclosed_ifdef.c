/*
 * Rule: DCL15-C
 * Source: custom
 * Status: FAIL - Should trigger DCL15-C violation
 * Description: A function under an `#ifdef` no `#endif` closes, as in a
 * truncated file. Left in place, the open conditional runs to the end of the
 * file and the parse buries the definition in an ERROR node, so it was never
 * read. No configuration compiles an unclosed conditional, so its directive
 * is blanked and its code kept: helper, which nothing outside the file
 * calls, has external linkage.
 * Expect: count=1
 */

#ifdef HAVE_EXTRA
int helper(int x)
{
    return x + 1;
}
