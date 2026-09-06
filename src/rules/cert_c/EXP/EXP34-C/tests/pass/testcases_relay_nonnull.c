/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 regression)
 * Status: PASS - Non-null value passed through local variable relay to
 *         callee that dereferences without checking. Safe because the
 *         pointer is known to be non-null (address-of local).
 */

#include <stdio.h>

void sink(int *ptr) {
    *ptr = 100;
    printf("Value: %d\n", *ptr);
}

int main() {
    int value = 0;
    int *data = &value;
    sink(data);
    return 0;
}
