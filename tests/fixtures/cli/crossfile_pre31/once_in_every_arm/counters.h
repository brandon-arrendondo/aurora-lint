#ifndef COUNTERS_H
#define COUNTERS_H

void record(int value);
void record_quietly(int value);

/* Both builds evaluate the argument exactly once. */
#ifndef NDEBUG
#define DBG_COUNT(x) record(x)
#else
#define DBG_COUNT(x) record_quietly(x)
#endif

#endif
