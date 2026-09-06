/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - main() passes NULL to unsafe_function() which dereferences it.
 *         Detected via intra-file prescan (call-site null state propagation).
 */

#include <stdio.h>

void unsafe_function(int *ptr) {
    // No NULL check before dereference
    *ptr = 100;
    printf("Value set to: %d\n", *ptr);
}

int main() {
    unsafe_function(NULL);
    return 0;
}