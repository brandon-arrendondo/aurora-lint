/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Post-decrement without checking for zero
 */

void post_decrement_unsafe(unsigned int value) {
    // Post-decrement without checking for 0
    unsigned int result = value--;  // Line 9 - VIOLATION

    // Use result...
}

int main(void) {
    post_decrement_unsafe(0);  // Will wrap to UINT_MAX
    return 0;
}
