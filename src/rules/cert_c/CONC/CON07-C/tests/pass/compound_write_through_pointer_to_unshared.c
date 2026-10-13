/*
 * Rule: CON07-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON07-C violation
 *
 * Compound operations through a pointer are judged by what the pointer
 * points at. None of these is known to point at a shared object: one points
 * at a thread-local array, one is a parameter, one is retargeted to an
 * object the caller supplies, and one points at a local array.
 */

static _Thread_local int tl_buf[4];
static _Thread_local int *tl_cursor = tl_buf;

void step_local(void) { (*tl_cursor)++; }

void through_param(int *p) { (*p)++; }

static int shared[4];
static _Thread_local int *moved = shared;

void retarget(int *other) { moved = other; }

void step_moved(void) { (*moved)++; }

void own(void) {
  int local[2] = {0, 0};
  int *q = local;
  q[0] += 1;
}
