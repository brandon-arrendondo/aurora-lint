/*
 * Rule: INT31-C
 * Source: custom
 * Status: PASS - Should NOT trigger INT31-C violation
 * Description: int-to-double and float-to-double are widening conversions,
 * not narrowing ones -- neither loses data, so INT31-C must not flag them.
 * float-to-double specifically is left to FLP34-C (floating-to-floating
 * precision), which this rule intentionally does not duplicate.
 */

void func(int whole, float ratio) {
    double a = whole;
    double b = ratio;
    (void)a;
    (void)b;
}
