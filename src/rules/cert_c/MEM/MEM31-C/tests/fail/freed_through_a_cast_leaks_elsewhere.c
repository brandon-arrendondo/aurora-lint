/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Reading `free((void *) p)` as a release of `p` credits only
 * the paths that reach it. A return before the cleanup label still leaks
 * the block, and freeing it twice through casts is still a double free.
 * Expect: count=3
 */

#include <stdlib.h>

void use(const char *);

int returns_before_the_label(int early)
{
    const char *a = malloc(8);

    if (a == NULL)
        goto bye;
    if (early)
        return -1; /* Expect: here */
    use(a);
bye:
    free((void *) a);
    return 0;
}

void freed_twice_through_casts(void)
{
    char *p = malloc(8);
    use(p);
    free((void *) p);
    free((char *) p); /* Expect: here */
}

int success_path_keeps_it(int key)
{
    const char *q = NULL;

    if ((q = malloc((size_t) key)) != NULL)
        use(q);
    if (key > 4)
        goto error;
    return 0; /* Expect: here */

error:
    free((void *) q);
    return -1;
}
