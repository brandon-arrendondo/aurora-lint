/*
 * Rule: SIG02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger SIG02-C violation
 */

#include <pthread.h>

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

/* THREAD 1 */
int do_work(void) {
  int result;
  /* ... */
  if ((result = pthread_mutex_lock(&mut)) != 0) {
    /* Handle error condition */
  }
  if ((result = pthread_cond_signal(&cond,&mut)) != 0) {
    /* Handle error condition */
  }
  if ((result = pthread_mutex_unlock(&mut)) != 0) {
    /* Handle error condition */
  }
}

/* THREAD 2 */
int wait_and_work(void) {
  if ((result = pthread_mutex_lock(&mut)) != 0) {
    /* Handle error condition */
  }
  while (!work_available()) {
    if ((result = pthread_cond_wait(&cond, &mut)) != 0) {
      /* Handle error condition */
    }
    /* ... */
  }
  if ((result = pthread_mutex_unlock(&mut)) != 0) {
    /* Handle error condition */
  }
  /* ... */
}