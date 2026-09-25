/*
 * Rule: EXP34-C
 * Source: testcases (assert-style macros that do not guard)
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * ADR-0010 D5 / ADR-0011: a check that some compilable configuration
 * removes guards nothing. CHECK has an NDEBUG arm that expands to nothing.
 * debugAssert only checks while a runtime switch is on (valkey's
 * debugServerAssert shape). ASSUME's failure branch is only
 * __builtin_unreachable, a compiler assumption with no runtime check. None
 * of them is a dominating check, so all three dereferences are reported.
 */

#include <stdlib.h>
#include <string.h>

#ifdef NDEBUG
#define CHECK(x) ((void)0)
#else
#define CHECK(x) do { if (!(x)) abort(); } while (0)
#endif

extern int enable_debug_assert;
#define hardAssert(_e) ((_e) ? (void)0 : abort())
#define debugAssert(_e) (enable_debug_assert ? hardAssert(_e) : (void)0)
#define ASSUME(x) do { if (!(x)) __builtin_unreachable(); } while (0)

void strippable(char *buf) {
    char *p = strchr(buf, ':');
    CHECK(p != NULL);
    *p = 0;
}

void runtime_gated(char *buf) {
    char *q = strchr(buf, ';');
    debugAssert(q != NULL);
    *q = 0;
}

void assumed(char *buf) {
    char *r = strchr(buf, ',');
    ASSUME(r != NULL);
    *r = 0;
}
