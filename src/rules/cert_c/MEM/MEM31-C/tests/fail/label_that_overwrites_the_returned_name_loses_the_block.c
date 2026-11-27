/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A cleanup label that returns a name hands the caller what
 * the name holds when it returns, not the block a jump carried there. A
 * label that writes the name first returns something else, and the block
 * is lost on the jump.
 * Expect: count=3
 */
#include <stdlib.h>
#include <string.h>

int check(const char *s);

char *nulled_before_return(const char *s)
{
    char *r = strdup(s);

    if (r == NULL)
        return NULL;
    if (check(r) < 0)
        goto fail; /* Expect: here */
    return r;

fail:
    r = NULL;
    return r;
}

char *replaced_before_return(const char *s)
{
    char *r = strdup(s);
    char *t;

    if (r == NULL)
        return NULL;
    t = strdup("fallback");
    if (t == NULL) {
        free(r);
        return NULL;
    }
    if (check(r) < 0)
        goto fail; /* Expect: here */
    free(t);
    return r;

fail:
    r = t;
    return r;
}
