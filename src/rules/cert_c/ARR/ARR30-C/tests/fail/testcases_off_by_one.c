/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR30-C violation
 * Reason: same loop-bound shape as the loop-overrun fixture beside it --
 * i <= 20 walks one past a 20-byte buffer. VRA gives `i` the range [0, 20]
 * in the loop body, whose max reaches the buffer's size.
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
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