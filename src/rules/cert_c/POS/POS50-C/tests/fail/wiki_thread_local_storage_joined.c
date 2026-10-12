/*
 * Rule: POS50-C
 * Source: wiki
 * Status: FAIL - Should trigger POS50-C violation
 *
 * CERT's POS50-C page offers this as compliant: createThread runs in the
 * main thread, and main joins the child before val goes away. CERT's
 * CON34-C page calls the same shape noncompliant, because another thread's
 * access to a thread-local (or automatic) object is implementation-defined
 * (C 6.2.4) however long the object lives. The two rules share one
 * analysis, which takes the strict reading by default: no credit for a
 * join, so passing &val is reported.
 */

/* Declare val as a thread-local value */
__thread int val;

void *childThread(void *val) {
  /* Correctly prints 1 */
  int *res = (int *)val;
  printf("Result: %d\n", *res);
  return NULL;
}

void createThread(pthread_t *tid) {
  val = 1;
  int result = pthread_create(tid, NULL, childThread, &val); /* violation */
  if (result != 0) {
    /* Handle error */
  }
}

int main(void) {
  pthread_t tid;
  int result;
  createThread(&tid);
  if ((result = pthread_join(tid, NULL)) != 0) {
    /* Handle error */
  }
  return 0;
}