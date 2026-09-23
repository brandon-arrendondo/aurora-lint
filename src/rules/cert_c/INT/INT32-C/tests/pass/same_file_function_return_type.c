/*
 * Rule: INT32-C
 * Source: real-world (valkey src/kvstore.c:503
 *         `(random() % kvstoreSize(kvs)) + 1`)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: `kvstoreSize` is defined in this file as `unsigned long long`, so
 *         `random() % kvstoreSize(kvs)` converts to it and the `+ 1` is
 *         unsigned arithmetic. The call's type was "unknown" (no return type
 *         is kept anywhere) and the parenthesized left operand was typed
 *         from its TEXT, so the `+ 1` read as a signed addition. Same-file
 *         return types are now collected, and parentheses are looked
 *         through.
 */

#include <stdlib.h>

struct kvstore {
    unsigned long long count;
};

unsigned long long int kvstoreSize(struct kvstore *kvs)
{
    return kvs->count;
}

unsigned long pick(struct kvstore *kvs)
{
    unsigned long target = kvstoreSize(kvs) ? (random() % kvstoreSize(kvs)) + 1 : 0;
    return target;
}
