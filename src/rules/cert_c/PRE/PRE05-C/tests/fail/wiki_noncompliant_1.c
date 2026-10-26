/*
 * Rule: PRE05-C
 * Source: wiki
 * Status: FAIL - Should trigger PRE05-C violation
 *
 * Non-compliant: JOIN uses ## directly, so __LINE__ is not expanded
 * before concatenation, resulting in "assertion_failed_at_line___LINE__"
 */

#define JOIN(x, y) x ## y

#define static_assert(e) \
  typedef char JOIN(assertion_failed_at_line_, __LINE__) /* Expect: here */ \
    [(e) ? 1 : -1]