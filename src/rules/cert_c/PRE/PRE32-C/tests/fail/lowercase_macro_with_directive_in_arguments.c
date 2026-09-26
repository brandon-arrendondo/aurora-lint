/*
 * Rule: PRE32-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE32-C violation
 *
 * `mymacro` is lowercase, but it is a function-like macro, so a directive
 * inside its argument list is undefined behavior (C11 6.10.3p11). Whether a
 * call is a macro invocation comes from its definition, not its spelling.
 */

#define mymacro(a, b) ((a) + (b))

int total(int base)
{
    return mymacro(base,
#ifdef EXTRA
                   2
#else
                   1
#endif
    );  /* VIOLATION */
}
