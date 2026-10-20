/*
 * Rule: CON40-C
 * Source: testcases
 * Status: PASS - Should not trigger CON40-C violation
 *
 * A load and a store in the two arms of one if/else, with no loop around
 * them, never run on one path, so no loaded value reaches the store. Nor
 * does one whose local a call may have rewritten through its address.
 */

#include <stdatomic.h>

static atomic_int count;

void choose(int cond) {
    int v = 0;
    if (cond) {
        v = atomic_load(&count);
    } else {
        atomic_store(&count, v);
    }
    (void)v;
}

void read_value(int *out);

void replace(void) {
    int v = atomic_load(&count);
    read_value(&v);
    atomic_store(&count, v);
}
