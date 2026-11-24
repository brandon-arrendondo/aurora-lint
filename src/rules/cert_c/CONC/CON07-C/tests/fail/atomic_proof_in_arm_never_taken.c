/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=2
 *
 * After `#if 1` the `#else` is never taken, so `atomic_int` comes from the
 * project header and is not proven atomic; and an arm that stops at
 * `#error` proves nothing, so the atomic definition there is not the one in
 * effect.
 */

#if 1
#include "compat.h"
#else
#include <stdatomic.h>
#endif

#ifdef WANT_PLAIN
#include "inc/plain.h"
#else
#error "plain counts only"
struct counted {
  _Atomic int refs;
};
#endif

static atomic_int bytes;
static struct counted g;

void on_bytes(int n) { bytes += n; }

void retain(void) { g.refs++; }
