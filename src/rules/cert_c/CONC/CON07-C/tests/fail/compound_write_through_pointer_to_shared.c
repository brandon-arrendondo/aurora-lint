/*
 * Rule: CON07-C
 * Source: testcases
 * Status: FAIL - Should trigger CON07-C violation
 *
 * Each function performs a compound operation through a pointer that only
 * ever points into a shared object. Where the pointer itself is stored does
 * not matter: a thread-local cursor into a shared array still mutates the
 * array, without synchronization.
 */

static int shared_buf[4];
static int total;
struct stats {
  int n;
};
static struct stats counters;

static _Thread_local int *cursor = shared_buf;

void step(void) { (*cursor)++; }

void bump(int i) { cursor[i] += 2; }

void count(void) {
  struct stats *s = &counters;
  s->n++;
}

void accumulate(void) {
  int *p = &total;
  *p = *p + 1;
}
