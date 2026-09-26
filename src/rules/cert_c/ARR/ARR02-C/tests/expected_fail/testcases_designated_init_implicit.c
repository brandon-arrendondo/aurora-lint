/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: EXPECTED_FAIL - the Implicit Size form, not detected yet
 *
 * A designated initializer still leaves the bound to the initializer (the
 * largest designator plus one), which is the construct CERT ARR02-C's
 * "Noncompliant Code Example (Implicit Size)" names. None of these is a
 * character array initialized by a string literal, so EX1 does not apply.
 * Moved out of tests/pass/ together with that noncompliant example.
 */

#include <stdio.h>

int main() {
    int sparse_array[] = {[0] = 1, [5] = 42, [10] = 100};

    char flags[] = {[2] = 1, [7] = 1, [15] = 1};

    double coordinates[][3] = {
        [0] = {1.0, 0.0, 0.0},
        [2] = {0.0, 0.0, 1.0}
    };

    int config[] = {
        [0] = 10,
        [50] = 500,
        [99] = 999
    };

    printf("Designated initializers with implicit bounds\n");

    return 0;
}