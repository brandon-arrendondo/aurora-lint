/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A `void **` freeing helper handed the address of a member or
 * an element releases that member or element, on the way through a cleanup
 * label as on any other path. `free(*&p)` releases `p`, since `*&p` is `p`.
 */
#include <stdlib.h>
#include <string.h>

struct s {
    char *f;
    char *g;
};

static void safe_free(void **pp)
{
    free(*pp);
    *pp = NULL;
}

int step(void);

int member_of_a_block(void)
{
    struct s *p = calloc(1, sizeof(*p));

    if (p == NULL)
        return -1;
    p->f = strdup("x");
    if (p->f == NULL)
        goto out;
    if (step())
        goto out;
    step();
out:
    safe_free((void **)&p->f);
    free(p);
    return 0;
}

int member_of_a_local(void)
{
    struct s v;

    v.f = strdup("x");
    if (v.f == NULL)
        return -1;
    if (step())
        goto out;
out:
    safe_free((void **)&v.f);
    return 0;
}

int element_of_an_array(void)
{
    char *arr[2];

    arr[0] = strdup("x");
    if (arr[0] == NULL)
        return -1;
    if (step())
        goto out;
out:
    safe_free((void **)&arr[0]);
    return 0;
}

int through_star_ampersand(void)
{
    char *p = malloc(4);

    if (p == NULL)
        return -1;
    if (step())
        goto out;
    step();
out:
    free(*&p);
    return 0;
}
