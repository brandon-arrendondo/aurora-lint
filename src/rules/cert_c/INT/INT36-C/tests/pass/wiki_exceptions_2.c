/*
 * Rule: INT36-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdio.h>
#include <pthread.h>


void *print_int(void *ptr) {
  intptr_t i = (intptr_t) ptr;
  printf("The number is %jd\n", i);
  return NULL;
}

int main(void) {
  pthread_t thr1;
  intptr_t i = 123;
  int result;

   if ((result = pthread_create(&thr1, NULL, print_int, (void *)i)) != 0) {
    /* Handle error */
  }

  pthread_exit(NULL);
  return 0;
}