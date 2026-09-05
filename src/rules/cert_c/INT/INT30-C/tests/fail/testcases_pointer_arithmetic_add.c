// sqc-test: prescan
// Needs the project context a real scan builds: the INT3x provenance gate
// runs in every configuration now, and without context it has no summaries
// to resolve this file's own callees against.
/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Using wrapped addition for pointer arithmetic
 */

void pointer_offset(int *base, unsigned int offset1, unsigned int offset2) {
    // Addition may wrap
    unsigned int total_offset = offset1 + offset2;  // Line 9 - VIOLATION

    int *ptr = base + total_offset;
    *ptr = 42;
}

int main(void) {
    int buffer[100];
    pointer_offset(buffer, 4000000000U, 1000000000U);  // Wrapped offset
    return 0;
}
