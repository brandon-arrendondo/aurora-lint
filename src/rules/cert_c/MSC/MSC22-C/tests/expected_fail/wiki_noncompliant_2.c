/*
 * Rule: MSC22-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: this example's violation is
 * longjmp() being invoked (from do_stuff(), via main()) after the function
 * containing the matching setjmp() call (g(), reached via setup() -> f())
 * has already returned -- resuming a terminated stack frame is UB.
 * Detecting this requires interprocedural call-stack-liveness reasoning
 * (is the setjmp-containing function's frame still active at every
 * longjmp() call site reachable from it) well beyond a structural AST
 * check; MSC22-C instead targets the two syntactic misuses that are
 * cleanly checkable: setjmp() used outside an allowed context, and a
 * non-volatile local read after longjmp() whose value changed since
 * setjmp() was called.
 */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

static jmp_buf buf;
static void bad(void);

static void g(void) {
  if (setjmp(buf) == 0) {
    printf("setjmp() invoked\n");
  } else {
    printf("longjmp() invoked\n");
  }
}

static void f(void) {
  g();
}

static void setup(void) {
  f();
}

void do_stuff(void) {
  void (*b)(void) = bad;
  /* ... */
  longjmp(buf, 1);
}

static void bad(void) {
  printf("Should not be called!\n");
  exit(1);
}

int main(void) {
  setup();
  do_stuff();
}