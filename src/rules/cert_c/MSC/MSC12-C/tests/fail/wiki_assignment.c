/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation
 *
 * Wrapped in a function for the same reason as fail/wiki_dereference.c: an
 * expression statement at file scope is not C the compiler accepts, and the
 * rule declines to report one (task 1004). The fragment form used to be
 * caught anyway, through the orphaned `;` its failed file-scope parse left
 * behind -- task 1006 closed that path too, since the same orphaned `;` is
 * how a macro argument containing a keyword and an EM_ASM JavaScript block
 * were being reported.
 */

void f(void) {
    int a;
    int b;
    /* ... */
    a == b;
}
