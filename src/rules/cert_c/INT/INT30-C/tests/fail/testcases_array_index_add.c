/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Using wrapped addition result as array index
 */

void array_access(unsigned int index, unsigned int offset) {
    int data[100];

    // Addition may wrap, leading to invalid array access
    unsigned int target_index = index + offset;  // Line 11 - VIOLATION
    data[target_index] = 42;
}

int main(void) {
    array_access(4000000000U, 1000000000U);  // Wrapped index
    return 0;
}
