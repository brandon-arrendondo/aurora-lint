/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * The usual guard that requires C11 atomics: the arm without them stops at
 * `#error`, so no translation unit that compiles takes it, and the include
 * in the other arm is in effect. The same guard around a struct definition
 * leaves the atomic definition the only one.
 */

#ifdef __STDC_NO_ATOMICS__
#error "C11 atomics required"
#else
#include <stdatomic.h>
#endif

#ifndef WANT_COUNTED
#error "counted objects required"
#else
struct counted {
  atomic_int refs;
};
#endif

static atomic_int bytes;
static struct counted g;

void on_bytes(int n) { bytes += n; }

void retain(void) { g.refs++; }
