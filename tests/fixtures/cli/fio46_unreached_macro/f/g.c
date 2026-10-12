#include "fl.h"

void g(FILE *fp) {
  fclose(fp);
  fgetc(fp);
}
