/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=7
 *
 * A member is atomic only by the declaration this file shows. A plain
 * member beside an atomic one, a member of a type this file does not
 * define, a member whose definitions disagree across `#if` arms, a member
 * of a structure a block redefines without the atomic member, an atomic
 * member of an atomic structure (C11 6.5.2.3p5), also when that structure
 * is an anonymous member, and a plain member reached through a pointer are
 * each a plain compound operation.
 */

#include <stdatomic.h>
#include "conn.h"

struct refcounted {
  atomic_int refs;
  int other;
};

#ifdef HAVE_ATOMIC_STATS
struct stats {
  atomic_long hits;
};
#else
struct stats {
  long hits;
};
#endif

struct tagged {
  atomic_int refs;
};

struct wrapped {
  _Atomic struct {
    _Atomic int refs;
  };
};

static struct refcounted g;
static struct wrapped w;
static struct refcounted *gp = &g;
static conn_t conn;
static struct stats st;
static _Atomic struct refcounted whole;

void bump_other(void) { g.other++; }

void bump_header_member(void) { conn.refs++; }

void bump_disputed(void) { st.hits += 1; }

void bump_redefined(void) {
  struct tagged {
    int refs;
  };
  static struct tagged t;
  t.refs++;
}

void bump_member_of_atomic(void) { whole.refs++; }

void bump_member_of_anonymous_atomic(void) { w.refs++; }

void bump_other_through_pointer(void) { gp->other++; }
