/*
 * Rule: EXP36-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdalign.h>
#include <assert.h>
 
void func(void) {
  /* Align c to the alignment of an int */
  alignas(int) char c = 'x';
  int *ip = (int *)&c; 
  char *cp = (char *)ip;
  /* Both cp and &c point to equally aligned objects */
  assert(cp == &c);
}