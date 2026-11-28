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

void offset_ints(void) {
    int data[40];
    size_t k = 4 * sizeof(int);

    int *ptr = data + k; /* Expect: here */
    *ptr = 55;
}

void allocated_end(void) {
    size_t m = 50 * sizeof(int);
    int *buffer = (int *)malloc(m);

    if (buffer) {
        int *end = buffer + m; /* Expect: here */
        *(end - 1) = 999;
        free(buffer);
    }
}

void copy_at_offset(void) {
    int src[40] = {0};
    int dest[40];
    size_t q = 5 * sizeof(int);

    memcpy(dest + q, src, 10 * sizeof(int)); /* Expect: here */
}
