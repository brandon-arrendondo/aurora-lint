/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 regression)
 * Status: PASS - NULL passed through local variable to a function that
 *         checks for NULL before dereferencing (early-return guard).
 */

#include <stdio.h>

void safe_sink(int *ptr) {
    if (ptr == NULL) {
        return;
    }
    *ptr = 100;
    printf("Value: %d\n", *ptr);
}

int main() {
    int *data = NULL;
    safe_sink(data);
    return 0;
}
