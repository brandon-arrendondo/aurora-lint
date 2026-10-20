/*
 * Rule: CON40-C
 * Source: synthetic
 * Status: PASS - two subscripts spelled alike name two elements when the
 * index calls a function, so neither element is read twice
 */

#include <stdatomic.h>

atomic_int slots[8];

int next_slot(int start);

int sum_two_slots(void) {
  return slots[next_slot(0)] + slots[next_slot(0)];
}
