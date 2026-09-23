/*
 * Rule: INT32-C
 * Source: task 1323
 * Status: FAIL - `long` is 32-bit on LLP64, so this addition is still a
 *         32-bit signed overflow on a Windows build and must keep firing.
 *
 * The companion to the PASS fixture: the width model widens to 64 bits only
 * for types that are 64-bit under EVERY data model the corpora build for.
 * Plain `long` is 64-bit on LP64 and 32-bit on LLP64 -- curl builds both --
 * so widening on it would silently drop an overflow that is real on
 * Windows. hostap's `os_time_t` is this exact shape. Same exclusion, and
 * the same reason, as task 916 gave for `unsigned long` on INT30-C's side.
 */

#include <stdlib.h>

typedef long portable_time_t;

void add_timeout(const char *pos, portable_time_t *out)
{
    portable_time_t now = atoi(pos);
    portable_time_t delta = atoi(pos + 1);

    *out = now + delta;
}
