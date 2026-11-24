/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `free(*pp)` at a cleanup label releases the block `pp`
 * points to, not `pp`. A path that jumps to such a label and frees only the
 * pointee still leaks `pp` itself, whether or not the dereference is cast.
 * Expect: count=4
 */

#include <stdlib.h>

void use(void *);

int frees_only_the_pointee(int k)
{
    char **pp = malloc(sizeof *pp);
    if (pp == NULL)
        return -1;
    *pp = NULL;
    if (k)
        goto out; /* Expect: here */
    use(pp);
    free(pp);
    return 0;
out:
    free(*pp);
    return -1; /* Expect: here */
}

int frees_only_the_pointee_through_a_cast(int k)
{
    char **pp = malloc(sizeof *pp);
    if (pp == NULL)
        return -1;
    *pp = NULL;
    if (k)
        goto out; /* Expect: here */
    use(pp);
    free(pp);
    return 0;
out:
    free(*(void **)pp);
    return -1; /* Expect: here */
}
