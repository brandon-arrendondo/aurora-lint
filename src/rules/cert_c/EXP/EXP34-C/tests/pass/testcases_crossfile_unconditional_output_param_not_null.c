/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP34-C violation (aurora_lint 1458).
 * Companion to fail/testcases_crossfile_conditional_output_param_null.c:
 * `always_get_info` writes `*out` on EVERY path (no conditional), so it
 * belongs in `unconditional_modifies_params` and `caller`'s `p` is
 * genuinely non-null after the call -- `apply_cross_file_output_params_null`
 * must still credit this case, not just stop crediting the conditional one.
 */

struct info {
    int val;
};

static struct info real_info = { 42 };

static void always_get_info(int n, struct info **out) {
    (void)n;
    *out = &real_info;
}

void caller(int n) {
    struct info *p = 0;
    always_get_info(n, &p);
    int v = p->val;
    (void)v;
}
