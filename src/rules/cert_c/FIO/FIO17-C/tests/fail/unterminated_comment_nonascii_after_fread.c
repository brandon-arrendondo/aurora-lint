/* Malformed: the non-ASCII comment is never closed. */
#include <stdio.h>
void f(FILE *fp) {
  char buf[16];
  fread(buf, 1, 15, fp);
  /* éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé
  buf[15] = 0;
}
