/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 64 void pointer null guard)
 * Status: PASS - NULL pointer passed via &data to callee expecting void*,
 *         callee casts to int** and checks for NULL before dereferencing.
 */

#include <stdio.h>

void safe_sink(void *dataVoidPtr) {
    int **dataPtr = (int **)dataVoidPtr;
    int *data = (*dataPtr);
    if (data != NULL) {
        printf("Value: %d\n", *data);
    }
}

void caller(void) {
    int *data = NULL;
    safe_sink(&data);
}
