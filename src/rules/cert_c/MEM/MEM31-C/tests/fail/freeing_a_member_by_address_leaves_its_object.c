/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The `out:` label releases `p->f` through `safe_free`, and
 * nothing else. `p` itself leaks on the jump to it and at its return, and
 * in `leaves_g` the `p->g` a helper handed `&p->f` never sees leaks too.
 * A release of a member is not a release of the object holding it.
 * Expect: count=4
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

void use(struct s *p);

int leaves_p(int k)
{
    struct s *p = malloc(sizeof(*p));

    if (p == NULL)
        return -1;
    p->f = malloc(4);
    if (k)
        goto out; /* Expect: here */
    use(p);
    free(p->f);
    free(p);
    return 0;
out:
    safe_free((void **)&p->f);
    return -1; /* Expect: here */
}

int leaves_g(void)
{
    struct s v;

    v.f = strdup("x");
    v.g = strdup("y"); /* Expect: here */
    safe_free((void **)&v.f);
    return 0; /* Expect: here */
}
