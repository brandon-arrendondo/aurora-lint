/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: PASS - allocation sizes declared size_t, and a handle that is no size
 *
 * Each size reaching the allocator is size_t by its declaration: a global,
 * a member, a typedef of size_t, a typedef of that typedef, strlen()'s
 * result, and sizeof with a constant. pCount is named for a count but is a pointer to a struct,
 * the allocator's handle, not its size.
 */
#include <stdlib.h>
#include <string.h>

typedef size_t buf_len_t;
typedef size_t cap_t;
typedef cap_t room_t;

struct buffer { size_t len; char *data; };
struct pool { int used; };

size_t g_size;

void *pool_alloc(struct pool *pCount, size_t n);

void *copy_all(struct buffer *b, const char *s, buf_len_t cap,
               struct pool *pCount) {
    char *p = malloc(g_size);
    char *q = malloc(b->len);
    char *r = malloc(strlen(s) + 1);
    char *t = malloc(sizeof(struct buffer) + 1);
    char *v = malloc(cap);
    void *w = pool_alloc(pCount, sizeof(struct buffer));
    room_t room_len = cap;
    char *x = malloc(room_len);
    free(p); free(q); free(r); free(t); free(v); free(x);
    return w;
}
