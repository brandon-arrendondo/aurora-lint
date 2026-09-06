/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 64 void pointer null propagation)
 * Status: FAIL - NULL pointer passed via &data to callee expecting void*,
 *         callee casts to int** and dereferences without null check.
 */

#include <stdio.h>

void sink(void *dataVoidPtr) {
    int **dataPtr = (int **)dataVoidPtr;
    int *data = (*dataPtr);
    printf("Value: %d\n", *data);
}

void caller(void) {
    int *data = NULL;
    sink(&data);
}
