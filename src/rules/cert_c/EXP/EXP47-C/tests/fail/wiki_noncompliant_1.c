/*
 * Rule: EXP47-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP47-C violation
 * Expect: count=1
 */

#include <stdarg.h>
#include <stddef.h>

void func(size_t num_vargs, ...) {
  va_list ap;  
  va_start(ap, num_vargs);
  if (num_vargs > 0) {
    unsigned char c = va_arg(ap, unsigned char); /* Expect: here */
    // ...
  }
  va_end(ap);
}
 
void f(void) {
  unsigned char c = 0x12;
  func(1, c);
}