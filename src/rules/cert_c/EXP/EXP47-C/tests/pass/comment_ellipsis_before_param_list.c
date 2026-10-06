/* `...` inside a comment before the parameter list must not reverse the slice. */
#include <stdarg.h>
int f /* ... */ (int n, ...) {
  va_list ap;
  va_start(ap, n);
  int x = va_arg(ap, int);
  va_end(ap);
  return x;
}
