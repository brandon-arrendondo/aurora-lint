/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP34-C violation
 */

/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: FAIL
 * Reason: `&p->lock` on a null `p` is undefined (C11 6.5.2.3: `p->lock`
 *         designates a member of the object `p` points to, and there is
 *         none), and the address handed to the callee is then written
 *         through. Forming the address is not an exemption; only `&*p` is.
 *
 *         Distilled from valkey src/unit/fuzzer_client.c
 *         (`pthread_create(&threads[i], ...)` on an unchecked malloc).
 */

#include <stdlib.h>

struct obj {
    int lock;
};

void lock_init(int *lock);

void unchecked(void)
{
    struct obj *p = malloc(sizeof *p);
    lock_init(&p->lock);
    free(p);
}
