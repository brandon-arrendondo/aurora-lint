/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * The C11 test with the include in its arm and `#error` in the `#else`:
 * the only arm a compiling translation unit takes includes the header.
 */

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#else
#error "C11 atomics required"
#endif

static atomic_uint bytes;

void on_bytes(unsigned n) { bytes += n; }
