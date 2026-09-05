/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 regression)
 * Status: FAIL - NULL assigned to local variable, then passed to a function
 *         that dereferences the parameter without checking.
 *         Detected via intra-file prescan (call-site null state propagation).
 */

#include <stdio.h>

void sink(int *ptr) {
    *ptr = 100;
    printf("Value: %d\n", *ptr);
}

int main() {
    int *data = NULL;
    sink(data);
    return 0;
}
