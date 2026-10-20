/*
 * Rule: CON40-C
 * Source: testcases
 * Status: FAIL - Should trigger CON40-C violation
 *
 * The split-statement form where the local is replaced on one branch only:
 * on the other, the loaded value still reaches the store.
 */

#include <stdatomic.h>

static atomic_int count;
int fallback(void);

void refresh(int cond) {
    int v = atomic_load(&count);
    if (cond) {
        v = fallback();
    }
    atomic_store(&count, v);
}
