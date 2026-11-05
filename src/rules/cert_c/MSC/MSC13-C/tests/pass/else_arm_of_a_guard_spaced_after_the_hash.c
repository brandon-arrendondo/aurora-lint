/*
 * Rule: MSC13-C
 * Source: synthetic reduction of an if/else split across a feature guard
 *   spelled with white space between `#` and the directive's name
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * `#  if` and `# endif` are the same directives as `#if` and `#endif`.
 * The statement after the `#endif` is the else body of `if (t == 1)`, so
 * `off = n + 1` is read by the return whenever that arm runs. Left
 * unrepaired, the `} else` is a parse error and the else body reads as an
 * unconditional overwrite of `off`.
 */
int use(int v);

int f(int t, int n)
{
    int off;
#  if defined(HAVE_A)
    if (t == 1) {
        off = n + 1;
    } else
# endif
    off = n + 2;
    return use(off);
}
