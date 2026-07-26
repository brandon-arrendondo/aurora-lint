/*
 * Rule: MSC22-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

static jmp_buf buf;
static void bad(void);

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
  if (setjmp(buf) == 0) {
    printf("setjmp() invoked\n");
  } else {
    printf("longjmp() invoked\n");
  }
  do_stuff();
}