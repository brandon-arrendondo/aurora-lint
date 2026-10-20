/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * The split-statement form through a local: the value loaded is
 * incremented in the local and stored back, a separate atomic read and
 * atomic write of the same object.
 */

#include <stdatomic.h>
#include <stddef.h>

static atomic_size_t head;

void advance(size_t n) {
    size_t h = atomic_load(&head);
    for (size_t i = 0; i < n; ++i) {
        h++;
    }
    atomic_store(&head, h);
}
