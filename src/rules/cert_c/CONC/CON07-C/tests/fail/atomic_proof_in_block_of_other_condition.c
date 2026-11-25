/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=2
 *
 * An earlier block's include is not in effect at a use whose block tests
 * the opposite (`#ifndef X` after `#ifdef X`), or the same name after a
 * `#define` of it between the two.
 */

#ifdef HAVE_ATOMICS
#include <stdatomic.h>
#endif

#ifndef HAVE_ATOMICS
static atomic_int bytes;

void on_bytes(int n) { bytes += n; }
#endif

#ifdef USE_C11
#include <stdatomic.h>
#endif

#define USE_C11 1

#ifdef USE_C11
static atomic_int hits;

void on_hit(void) { hits += 1; }
#endif
