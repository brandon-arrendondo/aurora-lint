/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Source: testcases (CERT's own EXP33-C noncompliant example, set_flag(n,
 * &sign), adapted to a pointer output)
 * Status: FAIL - Should trigger EXP34-C violation.
 * `maybe_get_info` writes `*out` only when `n > 0`; on every other path
 * `out`'s pointee is left untouched. `caller`'s `p` starts as a null
 * pointer, so on the `n <= 0` path `p` is still null after the call.
 * `apply_cross_file_output_params_null` used to mark `p` NotNull off the
 * raw MAY `modifies_params` set regardless of which path was taken --
 * unconditionally suppressing this finding, a false negative. Fixed to
 * require `unconditional_modifies_params` (minus `conditional_modifies_params`),
 * the same MUST-strength guarantee EXP33-C's own cross-file output-param
 * credit requires.
 */

struct info {
    int val;
};

static struct info real_info = { 42 };

static void maybe_get_info(int n, struct info **out) {
    if (n > 0) {
        *out = &real_info;
    }
}

void caller(int n) {
    struct info *p = 0;
    maybe_get_info(n, &p);
    int v = p->val;
    (void)v;
}
