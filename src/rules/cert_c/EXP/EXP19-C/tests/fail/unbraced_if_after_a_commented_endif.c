/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: A comment stands before `#endif` on its line, so that line
 * closes the `#if 0`, and the unbraced `if` after it is live in every build.
 * Expect: count=1
 */

void g(void);

void f(int c)
{
#if 0
    g();
/* old call */ #endif
    if (c)
        g();
}
