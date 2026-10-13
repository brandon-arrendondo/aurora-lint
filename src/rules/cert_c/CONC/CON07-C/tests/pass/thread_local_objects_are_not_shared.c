/*
 * Rule: CON07-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON07-C violation
 *
 * Objects with thread storage duration are each thread's own, however the
 * storage class is spelled and in whichever order: no other thread can
 * interleave with the compound operations on them.
 */

#include <threads.h>

static _Thread_local int hits;
_Thread_local static int misses;
static thread_local int retries;
static __thread int drops;

int tally(void) {
  hits++;
  misses += hits;
  retries = retries + misses;
  drops += retries;
  return hits + misses + retries + drops;
}
