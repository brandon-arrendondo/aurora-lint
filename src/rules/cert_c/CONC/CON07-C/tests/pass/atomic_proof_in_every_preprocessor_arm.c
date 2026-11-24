/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * A proof inside preprocessor arms holds when every arm that can be taken
 * gives it (an `#if 0` arm is never taken), or when the use is in the same
 * arm as the proof.
 */

#if 0
#include "compat.h"
#else
#include <stdatomic.h>
#endif

#ifdef WIDE_COUNTS
struct counted {
  atomic_llong refs;
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

#ifdef HAVE_EPOCH
struct epoch {
  _Atomic unsigned gen;
};
static struct epoch e;

void advance(void) { e.gen++; }
#endif
