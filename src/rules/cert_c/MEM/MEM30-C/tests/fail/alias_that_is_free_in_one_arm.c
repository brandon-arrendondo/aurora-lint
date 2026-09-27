/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: RELEASE is `free` when PLAIN_ALLOC is defined and the
 * project's own my_release otherwise. In the PLAIN_ALLOC build the call
 * frees p and the next line writes through it. Taking the last definition
 * met resolved RELEASE to my_release in every build.
 */

#include <stdlib.h>

void my_release(void *p);

#ifdef PLAIN_ALLOC
#define RELEASE free
#else
#define RELEASE my_release
#endif

void f(void)
{
    char *p = malloc(10);
    if (p == NULL)
        return;
    RELEASE(p);
    p[0] = 'x';
}
