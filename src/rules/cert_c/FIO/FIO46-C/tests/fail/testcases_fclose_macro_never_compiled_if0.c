/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the fclose macro is inside an #if 0, so it is never
 * compiled and the call is the library's fclose
 */

#include <stdio.h>

#if 0
#define fclose(f) my_close(f)
#endif

void f(FILE *fp) {
  fclose(fp);
  fgetc(fp);
}
