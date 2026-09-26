/*
 * Rule: ARR38-C
 * Source: regression (valkey serverAssert shape)
 * Status: PASS - Should NOT trigger ARR38-C violation
 *
 * A check macro with no NDEBUG arm aborts in every configuration, so the copy
 * after it is bounded in every configuration. It is credited because of what
 * it expands to, not because of its name (check_macros).
 *
 * Settings: stdlib_noreturn=true
 * The library contract that abort/exit never return is held on under every
 * preset: it is not what this fixture tests (the strict preset's
 * freestanding environment withdraws it; see
 * src/rules/cert_c/MEM/MEM30-C/tests/pass/stdlib_exit_branch_needs_stdlib_noreturn.c).
 */

#include <stdlib.h>
#include <string.h>

#define checkOrDie(_e) ((_e) ? (void)0 : abort())

void checked_bound(const unsigned char *src, size_t n) {
    unsigned char buf[64];
    checkOrDie(n <= sizeof(buf));
    memcpy(buf, src, n);
}
