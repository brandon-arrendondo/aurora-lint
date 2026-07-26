/*
 * Rule: ERR05-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <setjmp.h>

const errno_t ESOMETHINGREALLYBAD = 1;

jmp_buf exception_env;

void g(void) {
  /* ... */
  if (something_really_bad_happens) {
    longjmp(exception_env, ESOMETHINGREALLYBAD);
  }
  /* ... */
}

void f(void) {
  g();
  /* ... Do the rest of f ... */
}

/* ... */
if (setjmp(exception_env) != 0) {
  /*
   * If we get here, an error occurred; 
   * do not continue processing.
   */
}
/* ... */
f();
/* If we get here, no errors occurred */
/* ... */