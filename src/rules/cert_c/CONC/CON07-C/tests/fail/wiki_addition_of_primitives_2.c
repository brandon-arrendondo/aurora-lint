/*
 * Rule: CON07-C
 * Source: wiki
 * Status: FAIL - Should trigger CON07-C violation
 */

#include <stdatomic.h>

static atomic_int a;
static atomic_int b;

void init_ab(void) {
  atomic_init(&a, 0);
  atomic_init(&b, 0);
}

int get_sum(void) {
  return atomic_load(&a) + atomic_load(&b);
}
 
void set_values(int new_a, int new_b) {
  atomic_store(&a, new_a);
  atomic_store(&b, new_b);
}