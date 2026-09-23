/*
 * Rule: CON30-C
 * Source: task 415 regression
 * Status: FAIL - Should trigger CON30-C violation
 *
 * Two functions each declare their own LOCAL `tss_t key;` with the same
 * name. thread_a_worker() properly cleans up its key with
 * free(tss_get(key)). thread_b_worker()'s key is a distinct object (a
 * different local variable that happens to share the name "key") and is
 * never freed and has no destructor - a real leak. The two keys must not
 * be conflated just because they share a name.
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
  /* leaked: no free(tss_get(key)) here, no destructor */
}
