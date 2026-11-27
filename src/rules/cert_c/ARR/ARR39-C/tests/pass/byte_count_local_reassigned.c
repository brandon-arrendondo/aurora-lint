/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * A local is followed to its initializer only while nothing else sets it.
 * Each of these is reassigned, stepped or has its address taken, so its
 * value at the addition is not known to be a byte count.
 */

#include <stddef.h>

void set_index(size_t *out);

int *reassigned(int *ptr, size_t n) {
    size_t skip = sizeof(int);
    skip = n;
    return ptr + skip;
}

int *stepped(int *ptr) {
    size_t skip = sizeof(int);
    skip--;
    return ptr + skip;
}

int *address_taken(int *ptr) {
    size_t skip = sizeof(int);
    set_index(&skip);
    return ptr + skip;
}
