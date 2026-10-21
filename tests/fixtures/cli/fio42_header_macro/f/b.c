#include <stdio.h>

void b(const char *path) {
  FILE *f = fopen(path, "r");
  CLOSE(f);
}
