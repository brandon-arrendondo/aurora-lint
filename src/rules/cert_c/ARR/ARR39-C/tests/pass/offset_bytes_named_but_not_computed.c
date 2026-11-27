/*
 * Rule: ARR39-C
 * Source: testcases
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * `offset_bytes` is set to 20, and nothing in that value says it counts
 * bytes rather than ints: the name is no evidence (ADR-0006). The twin
 * whose offset is computed with sizeof is
 * fail/byte_count_local_computed_with_sizeof.c.
 */

#include <string.h>
#include <stddef.h>

void memcpy_sizeof_offset(void) {
    int src[40] = {0};
    int dest[40];
    size_t offset_bytes = 20;

    memcpy(dest + offset_bytes, src, 10 * sizeof(int));
}

int main(void) {
    memcpy_sizeof_offset();
    return 0;
}
