/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A cleanup label that hands a variable to a freeing helper by
 * address, `safe_free(&p)` or `safe_free((void **)&p)`, releases that
 * variable on every path into the label. A label that frees both the pointee
 * and the pointer releases both.
 */

#include <stdlib.h>

void use(void *);

static void safe_free(void **pp)
{
    free(*pp);
    *pp = NULL;
}

int released_through_a_cast_address(int k)
{
    char *p = malloc(8);
    if (p == NULL)
        return -1;
    if (k)
        goto out;
    use(p);
out:
    safe_free((void **)&p);
    return 0;
}

int released_through_a_parenthesized_address(int k)
{
    void *p = malloc(8);
    if (p == NULL)
        return -1;
    if (k)
        goto out;
    use(p);
out:
    safe_free(&(p));
    return 0;
}

int frees_the_pointee_and_the_pointer(int k)
{
    char **pp = malloc(sizeof *pp);
    if (pp == NULL)
        return -1;
    *pp = malloc(8);
    if (k)
        goto out;
    use(pp);
out:
    free(*pp);
    free(pp);
    return 0;
}
