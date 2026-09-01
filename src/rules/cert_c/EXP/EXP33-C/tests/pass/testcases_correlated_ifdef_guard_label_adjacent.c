/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 *
 * Companion to testcases_correlated_ifdef_guard.c (task 590), covering the
 * task 663 sub-shape: the READ site's own `#ifdef CONFIG_ELOOP_SELECT`
 * guard opens immediately after a bare goto-label, so
 * label_preproc_guard::blank_label_guarded_preproc (task 647) removes its
 * `preproc_ifdef` AST node entirely (tree-sitter-c's `labeled_statement`
 * grammar has no slot for a preprocessor directive right after a label).
 * Without task 663's text-marker fallback, enclosing_ifdef_guard_key sees
 * no ifdef ancestor at all for the read, so it can never correlate with the
 * write sites' real, unblanked `#ifdef CONFIG_ELOOP_SELECT` guard -- a
 * false "may be used uninitialized" (real example: hostap's eloop.c
 * eloop_run, `rfds`/`wfds`/`efds` freed under `out:` right after the
 * label).
 */
void *malloc(unsigned long size);
void free(void *p);

void f(void) {
    int *rfds;

#ifdef CONFIG_ELOOP_SELECT
    rfds = (int *)malloc(sizeof(int));
    if (rfds == 0)
        return;
#endif

    goto out;
out:
#ifdef CONFIG_ELOOP_SELECT
    free(rfds);
#endif
    return;
}
