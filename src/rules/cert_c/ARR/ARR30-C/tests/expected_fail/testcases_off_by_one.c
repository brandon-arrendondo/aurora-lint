/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: same loop-bound gap as the loop-
 * overrun fixture beside it -- i <= 20 walks one past a 20-byte buffer,
 * but the maximum index is a property of the loop rather than a constant
 * subscript, and ARR30-C does not derive it. Reports nothing with or
 * without -d. A genuine ARR30-C violation.
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: EXPECTED FAIL
 * Reason: Classic off-by-one error in loop condition
 */

#include <stdio.h>

int main(void) {
    char buffer[20];
    const char* message = "Hello World";

    // Off-by-one error: should be i < 20, not i <= 20
    for (int i = 0; i <= 20; i++) {
        if (message[i] != '\0') {
            buffer[i] = message[i];
        } else {
            buffer[i] = '\0';
            break;
        }
    }

    printf("Buffer: %s\n", buffer);
    return 0;
}