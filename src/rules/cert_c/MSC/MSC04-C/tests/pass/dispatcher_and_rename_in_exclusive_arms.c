/*
 * Rule: MSC04-C
 * Source: aurora-lint
 * Status: PASS - with USE_DISPATCH, step calls run_c, and run_c calls
 *         step_c, a different function. Without it, run_c and step_c are
 *         renamed to run and step, and step is not defined. The renames
 *         and step's call never meet in one build, so nothing recurses.
 */
#if !defined(USE_DISPATCH)
#define run_c run
#define step_c step
#endif

int step_c(int n);

int run_c(int n) {
    return step_c(n) + 1;
}

#if defined(USE_DISPATCH)
int step(int n) {
    return run_c(n) * 2;
}
#endif
