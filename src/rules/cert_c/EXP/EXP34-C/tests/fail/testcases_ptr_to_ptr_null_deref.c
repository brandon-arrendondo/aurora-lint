/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 63 pointer-to-pointer null propagation)
 * Status: FAIL - NULL pointer passed via &data to callee expecting int**,
 *         callee dereferences *dataPtr without null check.
 */

#include <stdio.h>

void sink(int **dataPtr) {
    int *data = *dataPtr;
    printf("Value: %d\n", *data);
}

void caller(void) {
    int *data = NULL;
    sink(&data);
}
