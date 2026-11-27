/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=3
 *
 * A local that only its initializer sets holds that initializer's value
 * wherever it is read. Each of these is computed with sizeof, so it counts
 * bytes, and adding it to an int pointer scales it again.
 */

#include <stdlib.h>
#include <string.h>
#include <stddef.h>

void byte_offset(void) {
    int data[40];
    size_t byte_offset = 4 * sizeof(int);

    int *ptr = data + byte_offset; /* Expect: here */
    *ptr = 55;
}

void malloc_size_offset(void) {
    size_t alloc_size = 50 * sizeof(int);
    int *buffer = (int *)malloc(alloc_size);

    if (buffer) {
        int *end = buffer + alloc_size; /* Expect: here */
        *(end - 1) = 999;
        free(buffer);
    }
}

void memcpy_sizeof_offset(void) {
    int src[40] = {0};
    int dest[40];
    size_t offset_bytes = 5 * sizeof(int);

    memcpy(dest + offset_bytes, src, 10 * sizeof(int)); /* Expect: here */
}
