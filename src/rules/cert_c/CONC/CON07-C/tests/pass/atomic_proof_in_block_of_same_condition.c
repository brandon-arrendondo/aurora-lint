/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * A use inside `#ifdef X` is in effect only where an earlier `#ifdef X`
 * block was taken too, when nothing between defines or undefines `X`: the
 * include in the earlier block is in effect there, and of two definitions
 * of a tag in its arms, only the first arm's.
 */

#ifdef HAVE_STDATOMIC_H
#include <stdatomic.h>
#endif

#ifdef HAVE_STDATOMIC_H
struct counted {
  atomic_int refs;
};
#else
struct counted {
  int refs;
};
#endif

#ifdef HAVE_STDATOMIC_H
static atomic_int bytes;
static struct counted g;

void on_bytes(int n) { bytes += n; }

void retain(void) { g.refs++; }
#endif
