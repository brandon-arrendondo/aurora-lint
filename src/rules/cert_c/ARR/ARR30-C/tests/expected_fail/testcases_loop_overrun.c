/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the out-of-bounds index comes from a
 * loop bound (i <= 5 over a five-element array), and ARR30-C's buffer-
 * bounds check reports a constant subscript such as numbers[5] but does
 * not derive a loop's maximum index from the CFG/VRA state. Reports
 * nothing in any shipped configuration, with or without -d; the green
 * result this fixture used to give came from the test harness running the
 * rule with no CFGs and no value ranges at all, which no invocation of the
 * tool produces. A genuine ARR30-C violation.
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: EXPECTED FAIL
 * Reason: Loop condition allows access beyond array bounds
 */

#include <stdio.h>

int main(void) {
    int numbers[5] = {10, 20, 30, 40, 50};

    // Loop goes beyond array bounds (i <= 5 instead of i < 5)
    for (int i = 0; i <= 5; i++) {
        printf("numbers[%d] = %d\n", i, numbers[i]);
    }

    return 0;
}