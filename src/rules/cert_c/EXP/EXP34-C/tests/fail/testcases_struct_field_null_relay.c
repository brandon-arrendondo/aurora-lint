/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 67 struct field null propagation)
 * Status: FAIL - NULL stored in struct field, struct passed to callee,
 *         callee extracts and dereferences the field without null check.
 */

#include <stdio.h>

typedef struct {
    int *ptr;
} Wrapper;

void sink(Wrapper w) {
    int *data = w.ptr;
    printf("Value: %d\n", *data);
}

int main() {
    int *p = NULL;
    Wrapper myStruct;
    myStruct.ptr = p;
    sink(myStruct);
    return 0;
}
