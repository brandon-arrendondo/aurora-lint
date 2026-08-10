/*
 * Rule: CON30-C
 * Source: task 415 regression
 * Status: PASS - Should NOT trigger CON30-C violation
 *
 * Companion to the fail fixture with the same name: here BOTH functions
 * declare their own local `tss_t key;` and BOTH properly free the value
 * via free(tss_get(key)). Neither should be flagged, and per-function
 * scoping must not introduce a false positive either.
 */

#include <threads.h>
#include <stdlib.h>

void thread_a_worker(void) {
  tss_t key;
  if (thrd_success != tss_create(&key, NULL)) {
    return;
  }
  int *data = (int *)malloc(sizeof(int));
  tss_set(key, data);
  free(tss_get(key));
}

void thread_b_worker(void) {
  tss_t key;
  if (thrd_success != tss_create(&key, NULL)) {
    return;
  }
  char *buf = (char *)malloc(100);
  tss_set(key, buf);
  free(tss_get(key));
}
