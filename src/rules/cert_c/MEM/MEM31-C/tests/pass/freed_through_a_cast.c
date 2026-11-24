/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A cast hands `free` the same block, so `free((void *) p)`
 * releases `p` as `free(p)` does: in a straight line, at a cleanup label the
 * function falls through into, at a label whose frees sit under the same
 * `#ifdef` as the allocations, and through a freeing macro. A const pointer
 * freed through a cast to `void *` is the usual case.
 */

#include <stdlib.h>

#define QUOTAS 1
#define RELEASE(x) free(x)

void use(const char *);

char *lookup(int key)
{
    return malloc((size_t) key);
}

void straight_line(void)
{
    char *p = malloc(8);
    use(p);
    free((void *) p);
}

int const_pointer(void)
{
    const char *p = malloc(8);
    if (p == NULL)
        return -1;
    use(p);
    free((void *) p);
    return 0;
}

void falls_through_into_the_label(int key)
{
    const char *a = NULL;
    char *b = NULL;

    if ((a = lookup(key)) == NULL)
        goto bye;
    b = lookup(key + 1);
    if (b == NULL)
        goto bye;
    use(a);
    use(b);
bye:
    free((void *) a);
    free((void *) b);
}

const char *freed_under_the_same_ifdef(int key)
{
    const char *name = NULL;
#ifdef QUOTAS
    const char *quota = NULL;
#endif

    if ((name = lookup(key)) == NULL)
        goto error;
#ifdef QUOTAS
    if ((quota = lookup(key + 1)) != NULL)
        use(quota);
#endif
    if (key > 4)
        goto error;
#ifdef QUOTAS
    free((void *) quota);
#endif
    return name;

error:
    free((void *) name);
#ifdef QUOTAS
    free((void *) quota);
#endif
    return NULL;
}

void through_a_freeing_macro(void)
{
    char *p = malloc(8);
    use(p);
    RELEASE((void *) p);
}

int released_at_the_label_through_a_macro(int skip)
{
    char *p = malloc(8);
    if (p == NULL)
        return -1;
    if (skip)
        goto out;
    use(p);
out:
    RELEASE((void *) p);
    return 0;
}
