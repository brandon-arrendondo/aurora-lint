/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation
 *
 * The wiki prints this example as a bare fragment. It is wrapped in a
 * function here because an expression statement at file scope is not C the
 * compiler accepts, and the rule now declines to report one (task 1004): a
 * file-scope `expression_statement` only ever reaches a rule as parser
 * error-recovery debris from a declaration it could not resolve.
 */

void func(void) {
    int *p;
    /* ... */
    *p++;
}
