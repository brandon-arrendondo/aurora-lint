/*
 * Rule: CON07-C
 * Source: wiki
 * Status: FAIL - Should trigger CON07-C violation
 */

#include <pthread.h>

static int a;
static int b;

int get_sum(void) {
  return a + b;
}

void set_values(int new_a, int new_b) {
  a = new_a;
  b = new_b;
}

/* Establish real concurrent-execution context (task 608): get_sum/
 * set_values must be reachable from a thread-spawn root for CON07-C's
 * reachability gate to still fire on this fixture. */
void *worker(void *arg) {
  get_sum();
  set_values(1, 2);
  return 0;
}

int main(void) {
  pthread_t t;
  pthread_create(&t, 0, worker, 0);
  return 0;
}