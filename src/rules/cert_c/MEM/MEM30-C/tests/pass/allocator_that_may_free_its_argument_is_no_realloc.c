/*
 * Rule: MEM30-C
 * Source: real-world (valkey bitops.c: `o = lookupStringForBitCommand(c,
 *         ...)`, which frees the client only on an error path)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `lookup` returns a fresh object and frees its first argument
 * on one path only. That is not realloc's contract, so `c` is still live
 * after the call and using it is no use-after-free.
 */
#include <stdlib.h>

struct client {
    int broken;
    int db;
};

void *lookup(struct client *c, int key)
{
    if (c->broken) {
        free(c);
        return NULL;
    }
    return malloc((size_t)key + 1);
}

int command(struct client *c)
{
    void *o = lookup(c, 4);
    if (o == NULL) {
        return -1;
    }
    free(o);
    return c->db;
}
