/*
 * Rule: CON40-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdatomic.h>
 
int compute_sum(int n) {
  return n * (n + 1) / 2;
}