/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: LOG drops its arguments in one arm, but strerror's only side
 * effect is the static buffer it returns (and errno for an invalid code),
 * so the default policy does not count it; the strict policy does.
 */

#include <string.h>
#include <errno.h>

void log_it(const char *fmt, const char *msg);

#ifdef VERBOSE
#define LOG(fmt, msg) log_it(fmt, msg)
#else
#define LOG(fmt, msg)
#endif

void report(void) {
    LOG("failed: %s", strerror(errno));
}
