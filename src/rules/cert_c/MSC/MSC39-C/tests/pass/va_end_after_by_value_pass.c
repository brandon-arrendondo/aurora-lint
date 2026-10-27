/*
 * Rule: MSC39-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC39-C violation
 *
 * The list is passed by value to a function that calls va_arg on it, and
 * the caller's only later use is va_end, which is permitted.
 */

#include <stdarg.h>
#include <stddef.h>

static double sum(size_t count, va_list ap) {
  double total = 0.0;
  for (size_t i = 0; i < count; ++i) {
    total += va_arg(ap, double);
  }
  return total;
}

double total_of(size_t count, ...) {
  va_list ap;
  va_start(ap, count);
  double t = sum(count, ap);
  va_end(ap);
  return t;
}
