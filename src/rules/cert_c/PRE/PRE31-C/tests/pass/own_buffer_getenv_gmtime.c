/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: getenv and gmtime change nothing but the static object they return
 * (C11 7.22.4.6p4, 7.27.3p1), so the default policy does not count them when
 * LOG drops its arguments; the strict policy does.
 */

#include <stdlib.h>
#include <time.h>

void log_it(const char *fmt, const char *a, const struct tm *b);

#ifdef VERBOSE
#define LOG(fmt, a, b) log_it(fmt, a, b)
#else
#define LOG(fmt, a, b)
#endif

void report(const time_t *now) {
    LOG("home=%s at %p", getenv("HOME"), gmtime(now));
}
