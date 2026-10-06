/* Malformed: the initializing literal is never closed. */
#include <string.h>
void f(const char *s) {
  char buf[20] = "aé;
  strcat(buf, s);
  strcat(buf, "xyz");
}
