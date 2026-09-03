/*
 * Rule: INT31-C
 * Source: custom
 * Status: FAIL - Should trigger INT31-C violation
 * Description: Unguarded implicit assignment narrowing a double-typed
 * variable to int — the fractional part (and any out-of-int-range
 * magnitude) is silently lost.
 */

void func(double measurement) {
    int rounded = measurement;
    (void)rounded;
}
