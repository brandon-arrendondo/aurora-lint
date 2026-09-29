/*
 * Rule: MEM30-C
 * Source: real-world (sqlite sqlite3_close(db) -> sqlite3_free(db) via the
 *         xFree function pointer, then `db->x`)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * `mem_free` releases through a function pointer, which the analyzer cannot
 * follow, so nothing shows that `close_handle` frees `handle` and the later
 * `handle->id` is not reported. The `_free` in its name is not evidence.
 * A project whose deallocator works this way declares it
 * (`[environment.deallocators]`, or `--deallocator mem_free`), and the
 * access is then a use-after-free.
 */
#include <stdlib.h>

struct allocator {
    void (*xFree)(void *);
};

static struct allocator global_alloc = { free };

struct handle {
    int id;
};

/* `_free` suffix; releases via a function pointer the analyzer cannot follow. */
static void mem_free(void *p)
{
    global_alloc.xFree(p);
}

static void close_handle(struct handle *h)
{
    mem_free(h);
}

int use_after_close(struct handle *handle)
{
    close_handle(handle);
    return handle->id;
}
