/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: localtime may call tzset, which writes tzname and timezone, so it
 * is not in the own-buffer-only class; LOG dropping it is reported.
 */

#include <time.h>

void log_it(const char *fmt, const struct tm *b);

#ifdef VERBOSE
#define LOG(fmt, b) log_it(fmt, b)
#else
#define LOG(fmt, b)
#endif

void report(const time_t *now) {
    LOG("at %p", localtime(now));  // VIOLATION
}
