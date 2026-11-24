/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * `#if 1` is always taken, so its include is in effect with no `#else`, and
 * `#if (0)` is never taken, so the plain definition in it is not the one in
 * effect.
 */

#if 1
#include <stdatomic.h>
#endif

#if (0)
struct counted {
  int refs;
};
#else
struct counted {
  atomic_int refs;
};
#endif

static atomic_int bytes;
static struct counted g;

void on_bytes(int n) { bytes += n; }

void retain(void) { g.refs++; }
