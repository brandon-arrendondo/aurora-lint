/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation
 */

/*
 * Rule: EXP33-C - Do not read uninitialized memory
 * Status: PASS
 * Reason: The variable is a block-scope `static int` with no initializer. Objects with static or thread
 *         storage duration are zero-initialized when they have no
 *         initializer (C11 6.7.9p10), so every read below sees a determinate
 *         value. This fixture used to assert the opposite.
 */

#include <stdio.h>

/* Well-defined: Recursive function with uninitialized accumulator */
int unsafe_factorial(int n) {
    static int accumulator;  /* Uninitialized static */

    if (n <= 1) {
        return accumulator * 1;  /* Uses uninitialized static */
    }
    accumulator *= n;
    return unsafe_factorial(n - 1);
}

int main(void) {
    printf("Factorial: %d\n", unsafe_factorial(5));
    return 0;
}