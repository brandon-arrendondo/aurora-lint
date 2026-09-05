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
 * Reason: Addition of two unsigned integers without wrap check
 */

void func(unsigned int ui_a, unsigned int ui_b) {
    // No check for overflow - may wrap
    unsigned int usum = ui_a + ui_b;  // Line 9 - VIOLATION

    // Use usum...
}

int main(void) {
    func(4000000000U, 1000000000U);  // Will wrap
    return 0;
}
