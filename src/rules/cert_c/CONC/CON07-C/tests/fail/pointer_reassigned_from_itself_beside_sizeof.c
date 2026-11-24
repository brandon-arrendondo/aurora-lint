/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=2
 *
 * A `sizeof` operand reads nothing, but the same assignment can still read
 * the object it writes elsewhere: growing a shared array with `realloc`
 * reads the old pointer and stores the new one.
 */

#include <stdlib.h>

struct table {
  int *items;
};

static int *slots;
static struct table g;

void grow_slots(size_t n) { slots = realloc(slots, n * sizeof *slots); }

void grow_items(size_t n) { g.items = realloc(g.items, n * sizeof g.items[0]); }
