/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: FAIL
 * Reason: The `&p` out-parameter credit (task 1234) is withheld on POSITIVE
 *         evidence only: a summary proving the callee has a returning path
 *         that writes nothing through the parameter keeps p freed, and a
 *         callee that frees the POINTEE (`void **` safe-free wrapper) is a
 *         second free of p, not a refill.
 */

#include <stdlib.h>
#include <string.h>

/* writes *out only when flag is set: a proven non-writing return path */
int maybe_dup(int flag, char **out)
{
    if (flag)
        *out = strdup("b");
    return 0;
}

int maybe(int flag)
{
    char *h = strdup("x");
    free(h);
    maybe_dup(flag, &h);
    return (int)strlen(h);   /* use after free on the flag == 0 path */
}

/* frees *pp: the pointee */
void safe_free(void **pp)
{
    free(*pp);
    *pp = NULL;
}

void pointee_double_free(void)
{
    char *h = strdup("x");
    free(h);
    safe_free(&h);           /* double free through the pointee */
}

/* `&b->x` rebinds the FIELD only: the base b is still freed, and handing
 * the callee a slot inside freed memory is a use of it */
struct box { char *x; };
void fill(char **out);

void base_stays_freed(struct box *b)
{
    free(b);
    fill(&b->x);             /* member access on freed b */
}
