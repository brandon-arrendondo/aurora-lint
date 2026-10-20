/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * A local declared with _Atomic(int), read twice in one expression.
 */

#include <stdatomic.h>

int doubled(void) {
    _Atomic(int) local = 0;
    return local + local;
}
