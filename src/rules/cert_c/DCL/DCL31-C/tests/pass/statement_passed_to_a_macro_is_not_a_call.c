/*
 * Rule: DCL31-C
 * Source: custom
 * Status: PASS - Should NOT trigger DCL31-C violation
 * Description: TESTONLY takes a statement as its argument. Parsed as a
 * call, the `if` inside it reads as a call to a function named `if`, which
 * no declaration can name: a keyword is never a callee.
 */

#ifdef SQLITE_COVERAGE_TEST
# define TESTONLY(X)  X
#else
# define TESTONLY(X)
#endif

int count(int *p, int n)
{
    int k = 0;
    TESTONLY( if( n>=0 ) k++; )
    return k + p[0];
}
