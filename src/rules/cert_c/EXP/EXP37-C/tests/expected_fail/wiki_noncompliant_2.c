/*
 * Rule: EXP37-C
 * Source: wiki
 * Status: EXPECTED_FAIL - the call-through-an-incompatible-pointer form, not detected yet
 *
 * The violation is the call `fp('e', "Hello")`: `fp` holds `strchr`, whose
 * parameters are (const char *, int). The rule reports at the call, from
 * resolved types; the old report at the `(*fp)()` declaration is gone.
 */

#include <stdio.h>
#include <string.h>

char *(*fp)();

int main(void) {
  const char *c;
  fp = strchr;
  c = fp('e', "Hello");
  printf("%s\n", c);
  return 0;
}