/*
 * Rule: CON05-C
 * Source: testcases
 * Status: FAIL - Should trigger CON05-C violation
 *
 * A macro that replaces fputs only in a region no build compiles, or only
 * in builds that define a feature flag, leaves the library's fputs in every
 * other build. That fputs blocks while the mutex is held.
 */

#include <stdio.h>
#include <threads.h>

int buffer_append(const char *s, void *f);

#if 0
#define fputs(s, f) buffer_append(s, f)
#endif

#ifdef USE_BUFFERED_OUTPUT
#define fputs(s, f) buffer_append(s, f)
#endif

mtx_t m;

void report(const char *s) {
  mtx_lock(&m);
  fputs(s, stdout);
  mtx_unlock(&m);
}
