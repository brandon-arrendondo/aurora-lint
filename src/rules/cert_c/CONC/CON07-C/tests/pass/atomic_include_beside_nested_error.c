/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * An arm that holds a nested conditional stopping at `#error` whichever of
 * its arms is taken is never taken itself, so the include in the other
 * arm is the one in effect.
 */

#ifdef __STDC_NO_ATOMICS__
#if 1
#error "C11 atomics required"
#endif
#else
#include <stdatomic.h>
#endif

static atomic_int bytes;

void on_bytes(int n) { bytes += n; }
