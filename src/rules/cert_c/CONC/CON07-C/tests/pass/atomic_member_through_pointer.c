/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * A member the structure's definition declares atomic is an atomic object
 * whether it is written directly or through a pointer to the structure, so
 * `p->refs++` is one atomic read-modify-write, as `g.refs++` is.
 */

#include <stdatomic.h>

struct refcounted {
  atomic_int refs;
  int other;
};

static struct refcounted g;
static struct refcounted *shared = &g;

void retain(void) { shared->refs++; }

void release(void) {
  struct refcounted *p = &g;
  p->refs -= 1;
}
