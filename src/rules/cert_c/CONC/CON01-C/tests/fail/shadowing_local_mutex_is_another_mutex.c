/*
 * Rule: CON01-C
 * Source: thread-API families (C11)
 * Status: FAIL - Should trigger CON01-C violation
 *
 * The function locks the file-scope mutex, then unlocks a block-scope
 * mutex of the same name that shadows it. The two are different objects,
 * so the unlock releases a mutex this function never acquired.
 */

#include <threads.h>

static mtx_t guard;
static int shared;

void update(void) {
    mtx_lock(&guard);
    shared++;
    {
        mtx_t guard;
        mtx_unlock(&guard); /* violation */
    }
}
