/*
 * Rule: CON04-C
 * Source: wiki
 * Status: FAIL - Should trigger CON04-C violation
 */

#include <stdio.h>
#include <threads.h>
 
const size_t thread_no = 5;
const char mess[] = "This is a test";

int message_print(void *ptr){
  const char *msg = (const char *) ptr;
  printf("THREAD: This is the Message %s\n", msg);
  return 0;
}

int main(void){
  /* Create a pool of threads */
  thrd_t thr[thread_no];
  for (size_t i = 0; i < thread_no; ++i) {
    if (thrd_create(&(thr[i]), message_print,
                    (void *)mess) != thrd_success) {
      fprintf(stderr, "Creation of thread %zu failed\n", i);
      /* Handle error */
    }
  }
  printf("MAIN: Thread Message: %s\n", mess);
  return 0;
}