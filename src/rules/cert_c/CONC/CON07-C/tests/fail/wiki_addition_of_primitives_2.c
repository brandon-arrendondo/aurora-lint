/*
 * Rule: CON07-C
 * Source: wiki
 * Status: FAIL - Should trigger CON07-C violation
 */

#include <pthread.h>
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

/* Establish real concurrent-execution context (task 608): get_sum/
 * set_values must be reachable from a thread-spawn root for CON07-C's
 * reachability gate to still fire on this fixture. */
void *worker(void *arg) {
  init_ab();
  get_sum();
  set_values(1, 2);
  return 0;
}

int main(void) {
  pthread_t t;
  pthread_create(&t, 0, worker, 0);
  return 0;
}