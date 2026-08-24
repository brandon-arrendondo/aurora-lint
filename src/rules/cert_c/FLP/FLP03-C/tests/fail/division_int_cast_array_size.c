/*
 * Rule: FLP03-C
 * Source: testcases (relocated from INT33-C, task 228); reshaped for task 517
 * Status: FAIL - Should trigger FLP03-C violation
 * Reason: `(double)sum / size` is FLOATING-POINT division (the dividend is cast
 *         to double, promoting the int divisor to double). `size` comes from
 *         `atoi(getenv(...))`, an untrusted full-range source (task 517's
 *         opt-in provenance gate), and is never validated before the division —
 *         a floating-point divide-by-zero (inf/nan) that must be detected and
 *         handled. This is FLP03-C's domain, NOT INT33-C (which covers only the
 *         integer divide-by-zero undefined behavior). Originally divided by a
 *         plain function parameter; task 517 found an unconstrained parameter
 *         alone isn't enough to flag under the redesigned rule (see the file
 *         header rationale in flp03_c.rs) since almost every real-world FP
 *         division divides by a parameter or local, and the rule has no
 *         cross-function taint propagation — so the risky source and the
 *         division must live in the same function for the gate to see it.
 */

#include <stdio.h>
#include <stdlib.h>

int main() {
    int values[] = {1, 2, 3};
    int sum = values[0] + values[1] + values[2];
    int size = atoi(getenv("ARR_SIZE"));  // No check for size == 0
    double avg = (double)sum / size;  // Divide by zero if size is 0
    printf("Average: %.2f\n", avg);
    return 0;
}
