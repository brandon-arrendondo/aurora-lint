/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * An element of an atomic array is an atomic object, and so is a member
 * that the structure's definition declares atomic. A compound assignment or
 * increment of one is a single atomic read-modify-write (C11 6.5.2.4p2,
 * 6.5.16.2p3), in a plain structure, in an array of them, through a typedef
 * or a nested structure, and in an anonymous member.
 */

#include <stdatomic.h>

typedef _Atomic int arow[4];

struct refcounted {
  atomic_int refs;
  int other;
};

struct slot {
  _Atomic int uses;
};

typedef struct {
  _Atomic(unsigned) gen;
} epoch_t;

struct outer {
  struct refcounted inner;
  union {
    atomic_long total;
    long spare;
  };
};

static _Atomic int counters[8];
static atomic_int sizes[8];
static _Atomic(int) pending[8];
static arow grid[2];
static struct refcounted g;
static struct slot slots[4];
static epoch_t epoch;
static struct outer o;

void count(int i) { counters[i]++; }

void grow(int i, int n) { sizes[i] += n; }

void settle(int i) { pending[i] -= 1; }

void mark(int i, int j) { grid[i][j]++; }

void retain(void) { g.refs++; }

void use(int i) { slots[i].uses += 1; }

void advance(void) { epoch.gen++; }

void nest(void) { o.inner.refs--; }

void add(long n) { o.total += n; }
