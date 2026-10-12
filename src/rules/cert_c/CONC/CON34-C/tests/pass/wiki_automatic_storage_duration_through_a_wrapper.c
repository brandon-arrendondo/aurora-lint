/*
 * Rule: CON34-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON34-C violation
 *
 * CERT's noncompliant example. main() hands &val to create_thread(), whose
 * thrd_create() receives it as the pointer parameter val: the address of an
 * automatic object reaches the thread through another function, which a
 * reading of one call cannot see. It was reported only by a presumption that
 * any pointer parameter may hold automatic storage, and that presumption is
 * not the ruled form, so it is not reported.
 */

#include <threads.h>
#include <stdio.h>

int child_thread(void *val) {
  int *result = (int *)val;
  printf("Result: %d\n", *result);  /* Correctly prints 1 */
  return 0;
}
 
void create_thread(thrd_t *tid, int *val) {
  if (thrd_success != thrd_create(tid, child_thread, val)) {
    /* Handle error */
  }
}
 
int main(void) {
  int val = 1;
  thrd_t tid;
  create_thread(&tid, &val);
  if (thrd_success != thrd_join(tid, NULL)) {
    /* Handle error */
  }
  return 0;
}