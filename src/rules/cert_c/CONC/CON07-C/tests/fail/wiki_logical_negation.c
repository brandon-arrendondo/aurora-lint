/*
 * Rule: CON07-C
 * Source: wiki
 * Status: FAIL - Should trigger CON07-C violation
 */

#include <pthread.h>
#include <stdbool.h>

static bool flag = false;

void toggle_flag(void) {
  flag = !flag;
}

bool get_flag(void) {
  return flag;
}

/* Establish real concurrent-execution context (task 608): toggle_flag/
 * get_flag must be reachable from a thread-spawn root for CON07-C's
 * reachability gate to still fire on this fixture. */
void *worker(void *arg) {
  toggle_flag();
  get_flag();
  return 0;
}

int main(void) {
  pthread_t t;
  pthread_create(&t, 0, worker, 0);
  return 0;
}