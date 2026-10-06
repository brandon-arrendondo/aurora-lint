/* A non-ASCII character in the initializing literal must not shift the content-length scan. */
#include <string.h>
void f(const char *s) {
  char buf[20] = "aé";
  strcat(buf, s);
  strcat(buf, "xyz");
}
