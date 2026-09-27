/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Settings: pre31_unknown_call_pure=false
 * Reason: with the policy relaxation withdrawn, strerror is judged by the
 * library contract as written: a later call may overwrite its buffer and
 * POSIX lets it set errno, so LOG dropping it is reported even in a hosted
 * environment.
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
    LOG("failed: %s", strerror(errno));  // VIOLATION
}
