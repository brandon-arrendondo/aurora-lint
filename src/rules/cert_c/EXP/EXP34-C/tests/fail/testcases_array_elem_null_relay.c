/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 66 array element null propagation)
 * Status: FAIL - NULL pointer stored in array element, array passed to callee,
 *         callee extracts element and dereferences without null check.
 */

#include <stdio.h>

void sink(int *dataArray[]) {
    int *data = dataArray[2];
    printf("Value: %d\n", *data);
}

void caller(void) {
    int *data = NULL;
    int *dataArray[5];
    dataArray[2] = data;
    sink(dataArray);
}
