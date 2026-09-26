/*
 * Rule: DCL31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL31-C violation
 *
 * `COMPUTE_TOTAL` is a function-like macro, so the call expands to an
 * expression and there is no function to declare.
 */

#define COMPUTE_TOTAL(a, b) ((a) + (b))

int total(int a, int b)
{
    return COMPUTE_TOTAL(a, b);
}
