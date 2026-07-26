/*
 * Rule: MSC22-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC22-C violation
 */

jmp_buf buf;

void f(void) {
  int i = 0;
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