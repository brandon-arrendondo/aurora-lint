/*
 * Rule: EXP02-C
 * Source: task 1264 -- over-suppression guard for the preprocessor-condition
 *   exemption added in the same task
 * Status: FAIL - SHOULD trigger EXP02-C violation
 *
 * The exemption covers a `#if`/`#elif` CONDITION only. Code in the guarded
 * BODY is ordinary runtime code that really does short-circuit, so it must
 * keep firing. The cheap version of that exemption -- walk up to any
 * preproc_* ancestor, as `is_inside_preproc_conditional` does -- would
 * silently swallow this, and with it every finding inside every #ifdef block
 * in the corpus. This fixture fails loudly if anyone reaches for it.
 *
 * The increment is deliberate: a guard LHS with a non-mutating call on the
 * right (`n > 0 && consume(p)`) is exempt for unrelated reasons, so it would
 * pass whether or not the body were wrongly suppressed and would not test
 * anything.
 */
int guarded(int n, int count) {
#ifdef FEATURE_ENABLED
    if (n > 0 && count++) {
        return 1;
    }
#endif
    return 0;
}
