/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR02-C violation
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