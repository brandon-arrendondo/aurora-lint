/*
 * Rule: MEM31-C
 * Source: synthetic
 * Status: PASS - The block is freed after a call to the file's own exit()
 *
 * This file defines its own static exit(), which only increments a counter
 * and returns. The call does not end the program, so nothing is leaked at
 * it, and the free after it releases the block. Reporting the block as not
 * freed "before exit()" would name a termination that is not there
 * (ADR-0005, ADR-0006).
 */
#include <stdlib.h>

static int calls;

static void exit(int c)
{
    calls += c;
}

void work(void)
{
    char *p = malloc(16);
    if (p == NULL) {
        return;
    }
    p[0] = 'x';
    exit(1);
    free(p);
}
