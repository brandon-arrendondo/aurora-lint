/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - fclose is a macro for the file's own close function, so a
 * call to it is not the library's fclose and closes no stream
 */

#include <stdio.h>

#define fclose(f) my_close(f)

int my_close(FILE *f);

void f(FILE *fp) {
  fclose(fp);
  fgetc(fp);
}
