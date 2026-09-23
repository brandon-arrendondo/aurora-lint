/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: guards for an earlier round of changes. An unambiguously defined
 * FREE-named macro still frees; a use of the freed pointer itself (not its
 * address) after the free is still a use-after-free; two frees with no
 * preprocessor split between them are still a double-free.
 */

#include <stdlib.h>

#define MY_FREE(x) free(x)

int sink(char *p);

int still_caught(char *p, char *q)
{
    MY_FREE(p);
    int r = sink(p);          /* passing the freed pointer itself */

    free(q);
    free(q);                  /* plain double-free, same configuration */
    return r;
}
