/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=3
 *
 * A proof inside one preprocessor arm holds only where that arm is taken.
 * When the other arm takes `atomic_int` from a project header, as a pre-C11
 * compatibility layer does, or the struct definition from a header, or the
 * include sits in an `#if 0` arm, the object is not proven atomic and each
 * compound operation is plain.
 */

#if defined(__STDC_NO_ATOMICS__)
#include "compat.h"
#else
#include <stdatomic.h>
#endif

#if 0
#include <stdatomic.h>
#endif

#ifdef OWN_DEF
struct counted {
  _Atomic int refs;
};
#else
#include "inc/plain.h"
#endif

static atomic_int bytes;
static struct counted g;

void on_bytes(int n) { bytes += n; }

void retain(void) { g.refs++; }

void release(void) { --bytes; }
