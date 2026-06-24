/*
 * Rule: FLP03-C
 * Source: testcases (relocated from INT33-C, task 228)
 * Status: FAIL - Should trigger FLP03-C violation
 * Reason: `(double)distance / time` is FLOATING-POINT division (the dividend is
 *         cast to double). When time == 0 this is a floating-point divide-by-zero
 *         (inf/nan) that must be detected — that is FLP03-C's domain, NOT INT33-C
 *         (integer divide-by-zero UB only).
 */

#include <stdio.h>

int main() {
    int distance = 100;
    int time = 0;  // Zero time duration

    double speed = (double)distance / time;  // Divide by zero
    printf("Speed: %.2f units per time\n", speed);
    return 0;
}