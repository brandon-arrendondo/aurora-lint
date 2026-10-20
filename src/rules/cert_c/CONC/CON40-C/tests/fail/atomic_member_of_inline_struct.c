/*
 * Rule: CON40-C
 * Source: synthetic
 * Status: FAIL - the _Atomic member of an inline struct member is read twice
 */

#include <stdatomic.h>

struct holder {
  struct {
    _Atomic int live;
    int dead;
  } inner;
};

struct holder h;

int read_live_twice(void) {
  return h.inner.live + h.inner.live;
}
