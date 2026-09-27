#ifndef COUNTERS_H
#define COUNTERS_H

void record(int value);

/* A debug build records the count; a release build drops the argument, so
 * a side effect in it happens only in the debug build. */
#ifndef NDEBUG
#define DBG_COUNT(x) record(x)
#else
#define DBG_COUNT(x) ((void)0)
#endif

#endif
