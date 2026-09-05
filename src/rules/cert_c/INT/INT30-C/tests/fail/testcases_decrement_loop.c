/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Decrement in loop without checking for zero
 */

void countdown(unsigned int count) {
    unsigned int i;

    // Decrement without checking for 0 - will wrap to UINT_MAX
    for (i = count; i >= 0; i--) {  // Line 11 - VIOLATION (infinite loop if wraps)
        // Process...
        if (i < count - 100) break;  // Emergency exit
    }
}

int main(void) {
    countdown(10);
    return 0;
}
