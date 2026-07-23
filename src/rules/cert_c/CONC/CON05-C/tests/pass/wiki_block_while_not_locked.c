/*
 * Rule: CON05-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON05-C violation
 */

#include <stdio.h>
#include <threads.h>
 
mtx_t mutex;
 
int thread_foo(void *ptr) {
  int result;
  FILE *fp = fopen("SomeNetworkFile", "r");
 
  if (fp != NULL) {
    /* Work with the file */
    fclose(fp);
  }

  if ((result = mtx_lock(&mutex)) != thrd_success) {
    /* Handle error */
  }

  /* ... */

  if ((result = pthread_mutex_unlock(&mutex)) != 0) {
    /* Handle error */
  }

  return 0;
}