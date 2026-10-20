/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * The split-statement form through two locals: the loaded value is
 * copied into a second local, which is stored back.
 */

#include <stdatomic.h>

static atomic_int count;

void bump(void) {
    int v = atomic_load(&count);
    int w = v + 1;
    atomic_store(&count, w);
}
