/*
 * Rule: CON05-C
 * Source: wiki
 * Status: FAIL - Should trigger CON05-C violation
 */

#include <stdio.h>
#include <threads.h>
 
mtx_t mutex;

int thread_foo(void *ptr) {
  int result;
  FILE *fp;

  if ((result = mtx_lock(&mutex)) != thrd_success) {
    /* Handle error */
  }
 
  fp = fopen("SomeNetworkFile", "r");
  if (fp != NULL) {
    /* Work with the file */
    fclose(fp);
  }
 
  if ((result = mtx_unlock(&mutex)) != thrd_success) {
    /* Handle error */
  }

  return 0;
}

int main(void) {
  thrd_t thread;
  int result;

  if ((result = mtx_init(&mutex, mtx_plain)) != thrd_success) {
    /* Handle error */
  }

  if (thrd_create(&thread, thread_foo, NULL) != thrd_success) {
    /* Handle error */
  }

  /* ... */

  if (thrd_join(thread, NULL) != thrd_success) {
    /* Handle error */
  }

  mtx_destroy(&mutex);

  return 0;
}