/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * An atomic_fetch_add on an element and a plain read of the same element
 * in one expression are two accesses.
 */

#include <stdatomic.h>

static _Atomic unsigned long pending[4];

unsigned long add_job(int type) {
    return atomic_fetch_add(&pending[type], 1) + pending[type];
}
