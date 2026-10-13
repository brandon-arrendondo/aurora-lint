/*
 * Rule: POS52-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS52-C violation
 *
 * The branch taken when pthread_mutex_lock() fails does not hold the
 * mutex, so reporting the failure there blocks nobody.
 */

#include <pthread.h>
#include <stdio.h>

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
int shared;

int bump(void) {
  if (pthread_mutex_lock(&m) != 0) {
    fprintf(stderr, "lock failed\n");
    return -1;
  }
  shared++;
  pthread_mutex_unlock(&m);
  return 0;
}
