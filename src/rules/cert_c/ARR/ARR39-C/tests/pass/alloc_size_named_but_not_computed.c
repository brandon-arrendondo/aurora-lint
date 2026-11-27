/*
 * Rule: ARR39-C
 * Source: testcases
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * `alloc_size` is set to 200, and nothing in that value says it counts
 * bytes rather than ints: the name is no evidence (ADR-0006). The twin
 * whose size is computed with sizeof is
 * fail/byte_count_local_computed_with_sizeof.c.
 */

#include <stdlib.h>

void malloc_size_offset(void) {
    size_t alloc_size = 200;
    int *buffer = (int *)malloc(alloc_size);

    if (buffer) {
        int *end = buffer + alloc_size;
        *(end - 1) = 999;
        free(buffer);
    }
}

int main(void) {
    malloc_size_offset();
    return 0;
}
