/*
 * Rule: DCL39-C
 * Source: regression (task 412)
 * Status: PASS - Should NOT trigger DCL39-C violation
 *
 * struct_vars must be scoped per-function. A same-named local variable in
 * an unrelated function must never inherit struct-type info (and therefore
 * a padding-leak verdict) from a struct declared elsewhere in the file.
 * Here, `s` in has_padding() is an unrelated struct declared in a
 * different function, and `s` in send_int() is a plain int* parameter,
 * not a struct at all -- it must not be flagged.
 */

#include <unistd.h>

struct Sensitive {
  int a;
  char b;
  int c;
};

void has_padding(void) {
  struct Sensitive s;
  s.a = 1;
  s.b = 2;
  s.c = 3;
  /* Never passed to a trust-boundary function. */
}

int send_int(int *s) {
  return write(1, &s, sizeof(s));
}
