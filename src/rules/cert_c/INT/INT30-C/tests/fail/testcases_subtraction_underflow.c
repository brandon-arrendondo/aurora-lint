/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Subtraction of unsigned integers without underflow check
 */

void func(unsigned int ui_a, unsigned int ui_b) {
    // No check if ui_a < ui_b - may wrap
    unsigned int udiff = ui_a - ui_b;  // Line 9 - VIOLATION

    // Use udiff...
}

int main(void) {
    func(100U, 200U);  // Will underflow/wrap
    return 0;
}
