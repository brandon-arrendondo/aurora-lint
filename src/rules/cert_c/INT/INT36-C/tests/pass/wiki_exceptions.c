/*
 * Rule: INT36-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <assert.h>
#include <stdint.h>
 
void h(void) {
  intptr_t i = (intptr_t)(void *)&i;
  uintptr_t j = (uintptr_t)(void *)&j;
 
  void *ip = (void *)i;
  void *jp = (void *)j;
 
  assert(ip == &i);
  assert(jp == &j);
}