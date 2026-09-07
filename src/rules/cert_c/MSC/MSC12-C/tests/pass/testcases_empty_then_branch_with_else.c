/*
 * Rule: MSC12-C
 * Status: PASS - Should NOT trigger MSC12-C violation
 */

/*
 * Reason: an empty then-branch belonging to an `if` that has an `else` is
 * deliberate case enumeration, not dead code -- it absorbs its condition so
 * the later arms do not run for it. `if (a) { } else if (b) { f(); }` is NOT
 * equivalent to `if (b) { f(); }`: delete the empty arm and f() now runs
 * whenever a && b (task 999; real example: sqlite's vdbeapi.c
 * `if( xDel==0 ){ /* noop *\/ }else if( xDel==SQLITE_TRANSIENT ){ ... }`).
 *
 * Both the braced and the bare-`;` forms of the idiom appear here. A
 * STANDALONE empty `if` with no `else` stays a violation -- see
 * tests/fail/testcases_empty_if_body.c, which is CERT's own shape.
 */

extern void handle_transient(void);
extern void handle_other(void);

void bind_text(int how, int flag)
{
    if (how == 0) {
    } else if (how == 1) {
        handle_transient();
    } else {
        handle_other();
    }

    if (flag)
        ;
    else
        handle_other();
}
