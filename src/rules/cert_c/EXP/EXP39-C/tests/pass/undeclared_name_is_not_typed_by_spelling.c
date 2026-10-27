/*
 * Rule: EXP39-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP39-C violation
 *
 * `fnum` and `float_bits` are declared in a header this scan does not
 * see. Their names say nothing about their types, so the casts are not
 * reported.
 */

#include "counters.h"

long *as_long(void) {
  return (long *)&fnum;
}

int *as_int(void) {
  return (int *)&float_bits;
}
