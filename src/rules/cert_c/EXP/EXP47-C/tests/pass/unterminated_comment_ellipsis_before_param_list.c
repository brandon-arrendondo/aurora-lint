/* Malformed: the comment holding the `...` is never closed. */
#include <stdarg.h>
int f /* ... 
(int n, ...) {
  va_list ap;
  va_start(ap, n);
  return n;
}
