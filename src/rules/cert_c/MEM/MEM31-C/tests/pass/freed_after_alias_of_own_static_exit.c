/*
 * Rule: MEM31-C
 * Source: synthetic
 * Status: PASS - The block is freed after a call, through a macro alias, to
 * the file's own exit()
 *
 * `bail` expands to `exit`, and this file defines its own static exit(),
 * which only increments a counter and returns. The call does not end the
 * program, and the free after it releases the block. Reporting the block as
 * not freed "before exit()" would name a termination that is not there
 * (ADR-0005, ADR-0006).
 */
#include <stdlib.h>

static int counter;

static void exit(int c)
{
    counter += c;
}

#define bail exit

void work(void)
{
    char *p = malloc(16);
    if (p == NULL) {
        return;
    }
    p[0] = 'x';
    bail(1);
    free(p);
}
