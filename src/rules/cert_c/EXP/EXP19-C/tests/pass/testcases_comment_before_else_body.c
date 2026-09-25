/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP19-C violation
 */

/*
 * Rule: EXP19-C - Use braces for the body of an if, for, or while statement
 * Status: PASS
 * Reason: A comment between `else` and its braced body (or its braced
 *         else-if) does not unbrace the body. tree-sitter-c keeps the comment
 *         as a child of the else clause, ahead of the statement.
 *
 *         Distilled from sqlite src/vdbesort.c (`}else` / `#endif` /
 *         a commented-out `if` condition directly before the brace), sqlite src/trigger.c (a block
 *         comment between `}else` / `#endif` and the next `if`) and mbedtls
 *         library/ecp.c (a comment opening an #if-guarded else-if arm).
 */

int f(int rc, int t)
{
    if (rc == 0) {
#if WORKERS > 0
        if (t) {
            rc = 1;
        } else
#endif
        /* if (!t) */ {
            rc = 2;
        }
    }
    return rc;
}

int g(int a, int b)
{
    int r = 0;
#ifndef OMIT_FEATURE
    if (a) {
        r = 1;
    } else
#endif

    /* if we are not initializing,
    ** build the entry
    */
    if (!b) {
        r = 2;
    }
    return r;
}

int h(int p, int q)
{
    int t = 0;
    if (p && q) {
        t = 1;
    } else
#if defined(RESTARTABLE)
    /* in progress? */
    if (q != 0) {
        t = 2;
    } else
#endif
    {
        t = 3;
    }
    return t;
}

int k(int a)
{
    int r = 0;
    if (a) {
        r = 1;
    } else /* fallback */ {
        r = 2;
    }
    return r;
}
