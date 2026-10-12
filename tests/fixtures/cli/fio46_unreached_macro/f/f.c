#include <stdio.h>

void f(FILE *fp) {
  fclose(fp);
  fgetc(fp);
}
