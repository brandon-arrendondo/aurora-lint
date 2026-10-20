/*
 * Rule: CON40-C
 * Source: testcases
 * Status: PASS - Should not trigger CON40-C violation
 *
 * An atomic_* call on an element names that element through &, which
 * does not access it, so the call is the only access. Only the index is
 * read beside it.
 */

#include <stdatomic.h>

static _Atomic unsigned long pending[4];
static atomic_long grid[4][4];

void add_job(int type) {
    atomic_fetch_add(&pending[type], 1);
}

unsigned long jobs(int type) {
    return atomic_load_explicit(&pending[type], memory_order_relaxed);
}

long cell(int i, int j) {
    return atomic_load(&grid[i][j]);
}

long through(_Atomic long *cells, int i) {
    return atomic_load(&cells[i]);
}
