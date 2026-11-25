/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * A pointer given the address of a member without a cast has that member's
 * type, so an atomic member of the structure it points to is atomic,
 * whatever structure holds that member.
 */

#include <stdatomic.h>

struct counted {
  _Atomic int refs;
};
struct owner {
  int pad;
  struct counted inner;
};

static struct owner g;

void retain(void) {
  struct counted *p = &g.inner;
  p->refs++;
}
