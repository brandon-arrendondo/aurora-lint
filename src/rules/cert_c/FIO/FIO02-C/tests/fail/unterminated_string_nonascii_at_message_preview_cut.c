/* Malformed: the non-ASCII text is an unterminated string inside the argument. */
#include <stdio.h>
int main(int argc, char **argv) {
  FILE *fp = fopen(argv[1  "éééééééééééééééééééééééééééééé], "w");
  if (fp) fclose(fp);
  return 0;
}
