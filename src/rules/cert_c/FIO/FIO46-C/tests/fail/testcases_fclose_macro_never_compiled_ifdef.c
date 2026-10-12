/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the fclose macro is inside an #ifdef of a name nothing defines, so it is never
 * compiled and the call is the library's fclose
 */

#include <stdio.h>

#ifdef NEVER_DEFINED_XYZ
#define fclose(f) my_close(f)
#endif

void f(FILE *fp) {
  fclose(fp);
  fgetc(fp);
}
