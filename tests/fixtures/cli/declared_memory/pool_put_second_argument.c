/* pool_put frees its second argument; the pool itself stays live. */
#include <stdlib.h>

struct pool;
extern void pool_put(struct pool *pool, void *block);

void put_twice(struct pool *pool) {
    char *p = malloc(8);
    if (p == NULL) return;
    pool_put(pool, p);
    pool_put(pool, p);
}
