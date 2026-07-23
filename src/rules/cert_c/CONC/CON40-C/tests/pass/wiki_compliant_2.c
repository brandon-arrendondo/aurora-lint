/*
 * Rule: CON40-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON40-C violation
 */

#include <stdatomic.h>
 
int compute_sum(int n) {
  return n * (n + 1) / 2;
}