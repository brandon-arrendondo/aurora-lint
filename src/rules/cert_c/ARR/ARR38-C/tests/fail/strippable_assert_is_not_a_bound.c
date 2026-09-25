/*
 * Rule: ARR38-C
 * Source: regression
 * Status: FAIL - Should trigger ARR38-C violation
 *
 * An assert stating the capacity contract is not a bound. NDEBUG strips it,
 * and in that configuration the copy is unchecked (ADR-0010 D5). Wrapping it
 * in `#ifndef NDEBUG` changes nothing: it is the same check, gone from the
 * same build. Companion to pass/abort_check_macro_bound.c, where the check
 * survives every configuration.
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
