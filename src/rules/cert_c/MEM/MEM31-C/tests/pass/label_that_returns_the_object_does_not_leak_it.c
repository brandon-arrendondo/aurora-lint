/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A jump to a label whose block ends by returning the object
 * hands it to the caller, which is not a leak: a label that returns it
 * directly, and one that skips ahead and falls through to the return.
 */
#include <stdlib.h>
#include <string.h>

int check(const char *s);
void append(char *buf, const char *s);

char *returned_at_the_label(const char *s)
{
    char *r = strdup(s);

    if (r == NULL)
        return NULL;
    if (check(r) < 0)
        goto out;
    append(r, "!");
out:
    return r;
}

char *skipped_to_the_return(const char *s, int quick)
{
    char *r = malloc(64);

    if (r == NULL)
        return NULL;
    if (quick)
        goto skip_suffix;
    append(r, s);
skip_suffix:
    append(r, ".");
    return r;
}
