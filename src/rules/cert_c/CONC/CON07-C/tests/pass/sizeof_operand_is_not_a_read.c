/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * The operand of `sizeof` is never evaluated, so `p = malloc(sizeof *p)`
 * stores to the shared pointer without reading it, and
 * `g.items = malloc(n * sizeof g.items[0])` stores to the member without
 * reading it.
 */

#include <stdlib.h>

struct table {
  int *items;
};

static struct entry {
  int key;
} *entries;
static struct table g;

void make_entries(size_t n) { entries = malloc(n * sizeof *entries); }

void make_items(size_t n) { g.items = malloc(n * sizeof g.items[0]); }
