/*
 * Rule: POS48-C
 * Source: testcases
 * Status: FAIL - Should trigger POS48-C violation
 *
 * CERT's noncompliant example with its threads in view: the workers lock
 * theLock, and the function that started them destroys it without joining
 * them first.
 */

#include <pthread.h>

pthread_mutex_t theLock;
int data;

void *worker(void *arg) {
  int value = *(int *)arg;
  int result;
  if ((result = pthread_mutex_lock(&theLock)) != 0) {
    /* Handle error */
  }
  data += value;
  if ((result = pthread_mutex_unlock(&theLock)) != 0) {
    /* Handle error */
  }
  return NULL;
}

int startAndFinish(int *values) {
  pthread_t threads[4];
  int result;
  for (int i = 0; i < 4; i++) {
    pthread_create(&threads[i], NULL, worker, &values[i]);
  }
  /* VIOLATION: the workers may still be using the lock */
  if ((result = pthread_mutex_destroy(&theLock)) != 0) {
    /* Handle error */
  }
  data++;
  return data;
}
