/*
 * Rule: DCL37-C
 * Status: FAIL - an #include under a platform macro such as _WIN32 or
 * _MSC_VER is compiled by the builds for that platform, and the
 * declarations below sit outside the #ifdef, so those builds have both.
 * Which platform this scan assumes does not decide it.
 * Expect: count=3
 */

#ifdef _WIN32
#include <stdbool.h>
#endif

#if defined(_MSC_VER)
#include <stdio.h>
#endif

enum answer { false, true }; /* Expect: here */

static int EOF; /* Expect: here */
