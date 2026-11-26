/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `create_scratch` returns a block `calloc` allocated, and
 * `create_either` returns one on one of its paths. `create_buf` returns,
 * on one path, what an allocator reached through a function pointer
 * handed it: no callee name says where that value came from, so it is not
 * known to be a stream. Typed `FILE *` or not, those are heap blocks, and
 * an `fclose` does not release them, so each caller still leaks what it
 * was handed, at the call and at the return.
 * Expect: count=6
 */
#include <stdio.h>
#include <stdlib.h>

static FILE *create_scratch(void)
{
    FILE *f = calloc(1, 64);
    return f;
}

static FILE *create_either(const char *name)
{
    if (name != NULL)
        return fopen(name, "r");
    return calloc(1, 64);
}

struct allocator {
    void *(*alloc)(size_t);
};
extern struct allocator g;

static FILE *create_buf(const char *name)
{
    if (name != NULL)
        return fopen(name, "r");
    return (FILE *)g.alloc(64);
}

int step(FILE *f);

int use_scratch(void)
{
    FILE *f = create_scratch(); /* Expect: here */

    if (f == NULL)
        return -1;
    step(f);
    fclose(f);
    return 0; /* Expect: here */
}

int use_either(const char *name)
{
    FILE *f = create_either(name); /* Expect: here */

    if (f == NULL)
        return -1;
    step(f);
    fclose(f);
    return 0; /* Expect: here */
}

int use_buf(const char *name)
{
    FILE *f = create_buf(name); /* Expect: here */

    if (f == NULL)
        return -1;
    step(f);
    fclose(f);
    return 0; /* Expect: here */
}
