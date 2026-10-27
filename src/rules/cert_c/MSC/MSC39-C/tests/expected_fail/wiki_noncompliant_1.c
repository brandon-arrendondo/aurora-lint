/*
 * Rule: MSC39-C
 * Source: wiki
 * Status: EXPECTED_FAIL - the caller's use after a by-value pass, not detected yet
 *
 * The violation is `va_arg(ap, double)` in print_reciprocals after `ap` was
 * passed by value to contains_zero, which calls va_arg on it. The old
 * report at contains_zero's parameter named the permitted half.
 */

#include <stdarg.h>
#include <stdio.h>
 
int contains_zero(size_t count, va_list ap) {
  for (size_t i = 1; i < count; ++i) {
    if (va_arg(ap, double) == 0.0) {
      return 1;
    }
  }
  return 0;
}

int print_reciprocals(size_t count, ...) {
  va_list ap;  
  va_start(ap, count);

  if (contains_zero(count, ap)) {
    va_end(ap);
    return 1;
  }

  for (size_t i = 0; i < count; ++i) {
    printf("%f ", 1.0 / va_arg(ap, double));
  }

  va_end(ap);
  return 0;
}