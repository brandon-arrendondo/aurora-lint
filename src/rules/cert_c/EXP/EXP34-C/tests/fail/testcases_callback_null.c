/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - main() passes NULL function pointer to process_data() which calls it.
 *         Detected via intra-file prescan (call-site null state propagation).
 */

#include <stdio.h>

typedef void (*callback_t)(int);

void process_data(int value, callback_t callback) {
    // No NULL check before calling function pointer
    callback(value);
}

int main() {
    process_data(42, NULL);
    return 0;
}