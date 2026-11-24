/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=2
 *
 * Only a compound assignment or an increment of a whole atomic object is one
 * atomic read-modify-write. `level = level + 1` loads and then stores, two
 * separate atomic accesses another thread can come between, and a member of
 * an atomic structure is not itself atomic.
 */

struct pair {
  int a;
  int b;
};

static _Atomic int level;
static _Atomic struct pair both;

void raise_level(void) { level = level + 1; }

void bump_member(void) { both.a++; }
