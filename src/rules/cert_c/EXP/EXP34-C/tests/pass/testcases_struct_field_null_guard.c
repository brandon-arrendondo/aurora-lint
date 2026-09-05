/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 — variant 67 struct field null guard)
 * Status: PASS - NULL stored in struct field, struct passed to callee,
 *         but callee checks for NULL before dereferencing.
 */

#include <stdio.h>

typedef struct {
    int *ptr;
} Wrapper;

void safe_sink(Wrapper w) {
    int *data = w.ptr;
    if (data != NULL) {
        printf("Value: %d\n", *data);
    } else {
        printf("data is NULL\n");
    }
}

int main() {
    int *p = NULL;
    Wrapper myStruct;
    myStruct.ptr = p;
    safe_sink(myStruct);
    return 0;
}
