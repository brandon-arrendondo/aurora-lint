/*
 * Rule: FLP03-C
 * Source: testcases (relocated from INT33-C, task 228)
 * Status: FAIL - Should trigger FLP03-C violation
 * Reason: `(double)f.numerator / f.denominator` is FLOATING-POINT division (the
 *         dividend is cast to double). When the denominator is 0 this is a
 *         floating-point divide-by-zero (inf/nan) that must be detected — that
 *         is FLP03-C's domain, NOT INT33-C (integer divide-by-zero UB only).
 */

#include <stdio.h>

typedef struct {
    int numerator;
    int denominator;
} Fraction;

int main() {
    Fraction f = {10, 0};  // Denominator is zero
    double result = (double)f.numerator / f.denominator;  // No validation
    printf("Result: %.2f\n", result);
    return 0;
}