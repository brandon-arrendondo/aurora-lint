/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Wrapped multiplication used for VLA size
 */

void create_vla(unsigned int rows, unsigned int cols) {
    // Multiplication may wrap
    unsigned int size = rows * cols;  // Line 9 - VIOLATION

    int vla[size];  // VLA with potentially wrapped size
    vla[0] = 42;
}

int main(void) {
    create_vla(100000U, 100000U);  // Will wrap
    return 0;
}
