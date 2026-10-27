/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL under the default preset with the exact-zero option off
 * Settings: flp00_exact_zero_comparison_exempt=false
 * Expect: count=1
 *
 * The option, not the preset, decides: withdrawn under the default preset,
 * the comparison with zero is reported.
 */

int is_unset(double x) {
    return x == 0.0; /* Expect: here */
}
