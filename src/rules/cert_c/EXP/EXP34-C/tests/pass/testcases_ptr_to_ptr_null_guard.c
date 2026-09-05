/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 63 pointer-to-pointer null guard)
 * Status: PASS - NULL pointer passed via &data to callee expecting int**,
 *         but callee checks for NULL before dereferencing.
 */

#include <stdio.h>

void safe_sink(int **dataPtr) {
    int *data = *dataPtr;
    if (data != NULL) {
        printf("Value: %d\n", *data);
    }
}

void caller(void) {
    int *data = NULL;
    safe_sink(&data);
}
