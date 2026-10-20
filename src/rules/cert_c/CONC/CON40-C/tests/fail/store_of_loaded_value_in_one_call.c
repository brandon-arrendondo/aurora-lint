/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * The split-statement form with the load inside the store's argument:
 * still a separate atomic read and atomic write of the same object.
 */

#include <stdatomic.h>
#include <stdbool.h>

static atomic_bool flag;

void toggle(void) {
    atomic_store(&flag, !atomic_load(&flag));
}
