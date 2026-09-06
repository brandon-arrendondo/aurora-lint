/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 66 array element null guard)
 * Status: PASS - NULL pointer stored in array element, array passed to callee,
 *         but callee checks for NULL before dereferencing.
 */

#include <stdio.h>

void safe_sink(int *dataArray[]) {
    int *data = dataArray[2];
    if (data != NULL) {
        printf("Value: %d\n", *data);
    }
}

void caller(void) {
    int *data = NULL;
    int *dataArray[5];
    dataArray[2] = data;
    safe_sink(dataArray);
}
