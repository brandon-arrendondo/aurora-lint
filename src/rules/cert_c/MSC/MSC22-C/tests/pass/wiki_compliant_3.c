/*
 * Rule: MSC22-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

jmp_buf buf;

void f(void) {
  volatile int i = 0;
  if (setjmp(buf) != 0) {
    printf("%i\n", i);
    /* ... */
  }
  i = 2;
  g();
}

void g(void) {
  /* ... */
  longjmp(buf, 1);
}