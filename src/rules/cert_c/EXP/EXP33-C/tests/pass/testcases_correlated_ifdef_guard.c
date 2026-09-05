/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `rfds` is declared
 * and malloc'd only inside `#ifdef CONFIG_ELOOP_SELECT` blocks, and read
 * (passed by value to `use()`) inside a LATER, separate
 * `#ifdef CONFIG_ELOOP_SELECT` block, with an unrelated
 * `#ifdef CONFIG_ELOOP_POLL` block in between that never touches `rfds`
 * (task 590; hostap's eloop_run pattern). aurora-lint has no preprocessor, so each
 * `#ifdef` occurrence is independently modeled as "maybe compiled, maybe
 * not" -- but `CONFIG_ELOOP_SELECT`'s defined-ness is one fixed fact for the
 * whole file, so the write and this read either both happen or both don't;
 * flagging this as "may be used uninitialized" would be a modeling artifact,
 * not a real risk.
 */
void use(int *p);
void do_something_unrelated(void);

void f(void) {
#ifdef CONFIG_ELOOP_SELECT
    int *rfds;
#endif
#ifdef CONFIG_ELOOP_SELECT
    rfds = (int *)malloc(sizeof(int));
    if (rfds == NULL)
        return;
#endif
#ifdef CONFIG_ELOOP_POLL
    do_something_unrelated();
#endif
#ifdef CONFIG_ELOOP_SELECT
    use(rfds);
#endif
}
