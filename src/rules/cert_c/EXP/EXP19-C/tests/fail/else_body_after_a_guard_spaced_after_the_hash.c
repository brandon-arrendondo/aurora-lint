/*
 * Rule: EXP19-C
 * Source: synthetic reduction of an if/else split across a feature guard
 *   spelled with white space between `#` and the directive's name
 * Status: FAIL - Should trigger EXP19-C violation
 * Expect: count=1
 *
 * `# ifdef` and `#  endif` are the same directives as `#ifdef` and
 * `#endif`. The statement after the `#endif` is the else body of
 * `if (t == 1)`, and it is not braced. Left unrepaired, the `} else` is a
 * parse error and the statement reads as one of its own after the if.
 */
int use(int v);

int f(int t, int n)
{
    int off;
# ifdef HAVE_A
    if (t == 1) {
        off = n + 1;
    } else
#  endif
    off = n + 2; /* Expect: here */
    return use(off);
}
