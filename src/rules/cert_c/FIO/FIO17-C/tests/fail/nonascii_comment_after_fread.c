/* A non-ASCII comment across the 200-byte window cut after fread must not panic. */
#include <stdio.h>
void f(FILE *fp) {
  char buf[16];
  fread(buf, 1, 15, fp);
  /* éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé */
  buf[15] = 0;
}
