/*
 * Rule: ARR38-C
 * Source: regression (valkey serverAssert shape)
 * Status: PASS - Should NOT trigger ARR38-C violation
 *
 * A check macro with no NDEBUG arm aborts in every configuration, so the copy
 * after it is bounded in every configuration. It is credited because of what
 * it expands to, not because of its name (check_macros).
 */

#include <stdlib.h>
#include <string.h>

#define checkOrDie(_e) ((_e) ? (void)0 : abort())

void checked_bound(const unsigned char *src, size_t n) {
    unsigned char buf[64];
    checkOrDie(n <= sizeof(buf));
    memcpy(buf, src, n);
}
