/*
 * Rule: FLP03-C
 * Source: testcases (relocated from INT33-C, task 228); reshaped for task 517
 * Status: FAIL - Should trigger FLP03-C violation
 * Reason: `(double)f.numerator / denominator` is FLOATING-POINT division (the
 *         dividend is cast to double). `denominator` comes from
 *         `atoi(getenv(...))`, an untrusted full-range source (task 517's
 *         opt-in provenance gate), and is never validated before the division —
 *         a floating-point divide-by-zero (inf/nan) that must be detected.
 *         This is FLP03-C's domain, NOT INT33-C (integer divide-by-zero UB
 *         only). Originally divided directly by an unvalidated struct field
 *         (`f.denominator`); task 517 found a bare struct-field/parameter
 *         divisor alone isn't enough to flag under the redesigned rule (see
 *         the file header rationale in flp03_c.rs) since almost every
 *         real-world FP division divides by a field or local, and the
 *         provenance gate doesn't trace field-expression taint — so this
 *         keeps the divisor as the plain, directly-tainted local instead.
 */

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int numerator;
    int denominator;
} Fraction;

int main() {
    int denominator = atoi(getenv("DEN"));  // No validation
    Fraction f = {10, denominator};
    double result = (double)f.numerator / denominator;
    printf("Result: %.2f\n", result);
    return 0;
}
