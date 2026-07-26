/*
 * Rule: CON40-C
 * Source: wiki
 * Status: FAIL - Should trigger CON40-C violation
 */

#include <stdatomic.h>

atomic_int n = 0;
  
int compute_sum(void) {
  return n * (n + 1) / 2;
}