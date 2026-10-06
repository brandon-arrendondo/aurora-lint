/* A non-ASCII comment across the 40-byte message preview cut must not panic. */
#include <stdio.h>
int main(int argc, char **argv) {
  FILE *fp = fopen(argv[1  /* éééééééééééééééééééééééééééééé */], "w");
  if (fp) fclose(fp);
  return 0;
}
