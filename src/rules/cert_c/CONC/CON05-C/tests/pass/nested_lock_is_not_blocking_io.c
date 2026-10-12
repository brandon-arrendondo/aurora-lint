/*
 * Rule: CON05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON05-C violation
 *
 * Acquiring a second mutex while holding the first can wait, but lock order
 * is CON35-C's question, not a blocking operation under this rule.
 */

#include <threads.h>

mtx_t outer, inner;
int a, b;

void move_one(void) {
    mtx_lock(&outer);
    mtx_lock(&inner);
    a--;
    b++;
    mtx_unlock(&inner);
    mtx_unlock(&outer);
}
