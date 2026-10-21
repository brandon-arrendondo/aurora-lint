/*
 * Rule: CON40-C
 * Source: synthetic
 * Status: PASS - a load and a store in two cases of a switch, the first
 * ending in a break (also inside a block), never both run
 */

#include <stdatomic.h>

atomic_int count;

int update(int kind, int value) {
  switch (kind) {
  case 0:
    value = atomic_load(&count);
    break;
  default:
    atomic_store(&count, value);
  }
  return value;
}

int update_in_blocks(int kind, int value) {
  switch (kind) {
  case 0: {
    value = atomic_load(&count);
    break;
  }
  default:
    atomic_store(&count, value);
  }
  return value;
}
