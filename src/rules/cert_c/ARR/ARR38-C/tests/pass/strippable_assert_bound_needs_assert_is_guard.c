/*
 * Rule: ARR38-C
 * Source: regression
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * An assert stating the capacity contract is the author writing down the
 * bound, and the default policy credits it (assert_is_guard), including one
 * wrapped in `#ifndef NDEBUG`. The strict policy does not: NDEBUG strips it,
 * and in that configuration the copy is unchecked (ADR-0010 D5). Companion
 * to abort_check_macro_bound.c, where the check survives every
 * configuration and bounds the copy under both policies.
 */

#include <assert.h>
#include <string.h>

void asserted_bound(const unsigned char *src, size_t n) {
    unsigned char buf[64];
    assert(n <= sizeof(buf));
    memcpy(buf, src, n);
}

void preproc_wrapped_assert(const unsigned char *src, size_t n) {
    unsigned char buf[64];
#ifndef NDEBUG
    assert(n <= sizeof(buf));
#endif
    memcpy(buf, src, n);
}
