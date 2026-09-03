// sqc-test: prescan
/*
 * Rule: INT31-C
 * Source: custom
 * Status: PASS - Should NOT trigger INT31-C violation
 * Description: Float value clamped to [0.0, 1.0] before being scaled and
 * narrowed to unsigned char. Suppressed by VRA (vra_proves_conversion_safe),
 * which already folds a guard-then-clamp range through the *255.0f multiply
 * and proves it fits in 8 unsigned bits -- not the textual
 * is_inside_bounds_checked_block heuristic, which only recognizes a named
 * limit macro (UCHAR_MAX etc.) in the guard condition, not a bare literal.
 * Needs the prescan marker: VRA/CFG setup is normally the CLI driver's job
 * before rule.check() runs, which the bare per-fixture harness doesn't do
 * unless asked (task 674 hit the same thing for INT10-C).
 */

unsigned char to_byte(float ratio) {
    if (ratio < 0.0f) ratio = 0.0f;
    if (ratio > 1.0f) ratio = 1.0f;
    return (unsigned char)(ratio * 255.0f);
}
