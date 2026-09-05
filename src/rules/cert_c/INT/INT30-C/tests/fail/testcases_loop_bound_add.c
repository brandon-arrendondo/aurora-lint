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
 * Reason: Wrapped addition used as loop bound
 */

void process_range(unsigned int start, unsigned int count) {
    // Addition may wrap
    unsigned int end = start + count;  // Line 9 - VIOLATION

    for (unsigned int i = start; i < end; i++) {
        // Process...
    }
}

int main(void) {
    process_range(4000000000U, 1000000000U);  // Wrapped end
    return 0;
}
