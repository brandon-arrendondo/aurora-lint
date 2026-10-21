/*
 * Rule: CON40-C
 * Source: synthetic
 * Status: PASS - a struct defined inside a function types only objects in
 * that function, not a file-scope pointer to another struct of that tag
 */

#include <stdatomic.h>

struct dup;
struct dup *gp;

void use_local(void) {
  struct dup {
    _Atomic int v;
    int w;
  } loc;
  (void)loc;
}

int read_twice(void) {
  return gp->v + gp->v;
}
