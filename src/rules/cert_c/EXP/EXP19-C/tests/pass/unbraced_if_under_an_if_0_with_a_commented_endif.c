/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP19-C violation
 * Description: A comment stands before the `#endif` of an `#if 0` on its line.
 * A comment is one space by the time directives are read, so that line closes
 * the conditional: the `#if 0` is not an unclosed one whose directive is
 * blanked, and the unbraced `if` in its arm stays dead.
 */

void g(void);

void f(int c)
{
#if 0
    if (c)
        g();
/* old check */ #endif
    g();
}
