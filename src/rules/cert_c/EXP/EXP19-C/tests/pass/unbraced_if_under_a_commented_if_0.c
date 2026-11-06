/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP19-C violation
 * Description: A comment stands before `#if 0` and its `#endif` on their
 * lines, the first comment spanning two lines. Both are directives, so the
 * unbraced `if` in the arm is dead.
 */

void g(void);

void f(int c)
{
/* old
   check */ #if 0
    if (c)
        g();
/* old check */ #endif
    g();
}
