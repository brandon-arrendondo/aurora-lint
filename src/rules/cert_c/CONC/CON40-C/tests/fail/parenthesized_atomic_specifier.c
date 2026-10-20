/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * _Atomic(int) at file scope with no storage class declares an atomic
 * object, though the parser reads the declaration as an error and a cast.
 */

#include <stdatomic.h>

_Atomic(int) total;

int square(void) {
    return total * total;
}
