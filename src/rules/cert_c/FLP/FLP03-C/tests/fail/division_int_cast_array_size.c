/*
 * Rule: FLP03-C
 * Source: testcases (relocated from INT33-C, task 228)
 * Status: FAIL - Should trigger FLP03-C violation
 * Reason: `(double)sum / size` is FLOATING-POINT division (the dividend is cast
 *         to double, promoting the int divisor to double). When size == 0 this
 *         is a floating-point divide-by-zero (inf/nan) that must be detected and
 *         handled. This is FLP03-C's domain, NOT INT33-C (which covers only the
 *         integer divide-by-zero undefined behavior).
 */

#include <stdio.h>

double calculate_average(int arr[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    // No check for size == 0
    return (double)sum / size;  // Divide by zero if size is 0
}

int main() {
    int empty_array[] = {};
    int size = 0;  // Empty array
    double avg = calculate_average(empty_array, size);
    printf("Average: %.2f\n", avg);
    return 0;
}