/*
 * Rule: DCL37-C
 * Status: FAIL - with <stdbool.h> included, `false` and `true` are reserved
 * there, and <inttypes.h> includes <stdint.h>, so `SIZE_MAX` is reserved too
 * (C 7.1.3, 7.8).
 * Expect: count=3
 */

#include <inttypes.h>
#include <stdbool.h>

enum answer { false, true }; /* Expect: here */

enum { SIZE_MAX = 80 }; /* Expect: here */
