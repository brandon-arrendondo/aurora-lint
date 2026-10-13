/*
 * Rule: CON33-C
 * Source: testcases
 * Status: FAIL - Should trigger CON33-C violation
 *
 * CON33-C lists ATOMIC_VAR_INIT among the library facilities that are not
 * safe to use concurrently. The initialization it performs is not atomic,
 * so it must not race with another thread's access to the same object.
 */

#include <stdatomic.h>

void reset(void) {
  atomic_int counter = ATOMIC_VAR_INIT(0);
  atomic_fetch_add(&counter, 1);
}
