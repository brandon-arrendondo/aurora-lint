/*
 * Rule: MEM30-C
 * Source: real-world (sqlite sqlite3_close(db) -> sqlite3_free(db) via the
 *         xFree function pointer, then `db->x`)
 * Status: FAIL - `handle->id` after `close_handle(handle)` is a
 *         use-after-free.
 *
 * `mem_free` is spelled like a deallocator and its body releases through a
 * function pointer, which the analyzer cannot see into: its summary frees
 * nothing and frees no field either -- "unseen", not "frees nothing". The
 * name guess stays a MAY-free (it is the only evidence there will ever be),
 * so the wrapper `close_handle` is credited and the later access is
 * reported -- marked for manual review, because the free is an inference
 * from a name. Twin of the PASS fixture, where the body DID say something.
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
