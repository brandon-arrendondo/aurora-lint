// sqc-test: prescan
/**
 * Rule: INT32-C
 * Source: testcases
 * Status: PASS - Should NOT trigger INT32-C violation.
 * `BIT(n)` expands to `(UL_CONST(1) << (n))` -- an unsigned long constant,
 * per seL4's real `util.h`. sqc has no preprocessor, so a call-like operand
 * such as `BIT(PT_INDEX_BITS)` previously fell through to "unknown" type
 * classification, making the subtraction look like risky signed arithmetic.
 * `UL_CONST` is a "make this an unsigned constant" helper macro (uses `##`
 * token-pasting in the real header to attach a `ul` suffix, which sqc's
 * macro engine deliberately never expands) recognized by name; `BIT`
 * transitively yields unsigned because its own definition invokes
 * `UL_CONST` (task 676; seL4's statedata.c `BIT(PT_INDEX_BITS) - 1`).
 */
#define UL_CONST(x) x
#define BIT(n) (UL_CONST(1) << (n))
#define MASK(n) (BIT(n) - UL_CONST(1))

#define PT_INDEX_BITS 9

void f(void) {
    int i = (int)(BIT(PT_INDEX_BITS) - 1);
    int j = (int)(BIT(PT_INDEX_BITS) - 2);
    int k = (int)(MASK(PT_INDEX_BITS));
    (void)i;
    (void)j;
    (void)k;
}
