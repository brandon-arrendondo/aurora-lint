#include "close.h"

void a(const char *path) {
  FILE *f = fopen(path, "r");
  CLOSE(f);
}
