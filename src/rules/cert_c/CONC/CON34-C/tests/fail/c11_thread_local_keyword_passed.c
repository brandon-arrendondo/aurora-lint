/*
 * Rule: CON34-C
 * Source: testcases
 * Status: FAIL - Should trigger CON34-C violation
 *
 * The objects are declared with the C11 _Thread_local keyword, in both
 * orders with static. Each thread has its own copy, so the new thread is
 * handed the creating thread's copy, which ends when that thread does.
 */

#include <threads.h>

static _Thread_local int first;
_Thread_local static int second;

int child(void *arg) { return *(int *)arg; }

void spawn(thrd_t *a, thrd_t *b) {
  thrd_create(a, child, &first);
  thrd_create(b, child, &second);
}
