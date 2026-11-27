/*
 * Rule: ARR39-C
 * Source: testcases
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * `byte_offset` is set to 16, and nothing in that value says it counts
 * bytes rather than ints: the name is no evidence (ADR-0006). The twin
 * whose offset is computed with sizeof is
 * fail/byte_count_local_computed_with_sizeof.c.
 */

#include <stddef.h>

void byte_offset(void) {
    int data[40];
    size_t byte_offset = 16;

    int *ptr = data + byte_offset;
    *ptr = 55;
}

int main(void) {
    byte_offset();
    return 0;
}
