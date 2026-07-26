/*
 * Rule: MSC22-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC22-C violation
 */

jmp_buf buf;

void f(void) {
  int i = setjmp(buf);
  if (i == 0) {
    g();
  } else {
    /* longjmp was invoked */
  }
}

void g(void) {
  /* ... */
  longjmp(buf, 1);
}