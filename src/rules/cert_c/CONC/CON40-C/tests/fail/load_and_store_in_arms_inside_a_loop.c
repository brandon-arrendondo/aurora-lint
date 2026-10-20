/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * A load in one arm and a store in the other, inside a loop: the value
 * loaded on one pass is stored on a later one.
 */

#include <stdatomic.h>

static atomic_int count;

void cycle(int n) {
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (i % 2 == 0) {
            v = atomic_load(&count);
        } else {
            atomic_store(&count, v + 1);
        }
    }
}
