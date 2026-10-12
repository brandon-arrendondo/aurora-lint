/*
 * Rule: POS48-C
 * Source: wiki
 * Status: PASS - Should NOT trigger POS48-C violation
 *
 * CERT's noncompliant example, as the page gives it. It names no thread:
 * whether worker() runs in a thread that may still be using theLock when
 * cleanupAndFinish() destroys it is decided by code the file does not show,
 * and cleanupAndFinish() itself never holds the lock. Only CERT's compliant
 * version's helper call tells the two apart, so the hazard is reported where
 * the file shows the thread (fail/wiki_noncompliant_with_threads.c).
 */

pthread_mutex_t theLock;
int data;

int cleanupAndFinish(void) {
  int result;
  if ((result = pthread_mutex_destroy(&theLock)) != 0) {
    /* Handle error */
  }
  data++;
  return data;
}

void worker(int value) {
  if ((result = pthread_mutex_lock(&theLock)) != 0) {
    /* Handle error */
  }
  data += value;
  if ((result = pthread_mutex_unlock(&theLock)) != 0) {
    /* Handle error */
  }
}