/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=1
 *
 * A nested `#error` that only one configuration reaches does not stop the
 * arm around it: with `STRICT` undefined that arm is taken without the
 * header, and `atomic_int` is not proven to be the library's.
 */

#ifdef __STDC_NO_ATOMICS__
#include "compat.h"
#ifdef STRICT
#error "C11 atomics required"
#endif
#else
#include <stdatomic.h>
#endif

static atomic_int bytes;

void on_bytes(int n) { bytes += n; }
