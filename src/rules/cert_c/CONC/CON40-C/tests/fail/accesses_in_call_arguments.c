/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * A call's arguments are part of the call's full expression, so an atomic
 * object passed twice is accessed twice in one expression.
 */

#include <stdatomic.h>

static atomic_int total;

void report(int, int);

void show(void) {
    report(total, total);
}
