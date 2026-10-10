/*
 * Rule: MEM31-C
 * Source: synthetic
 * Status: PASS - The block is freed after a call through a parameter named exit
 *
 * `exit` here is a function-pointer parameter, not the standard library's
 * exit(). The call returns, and the free after it releases the block
 * (ADR-0006).
 */
#include <stdlib.h>

void work(void (*exit)(int))
{
    char *p = malloc(16);
    if (p == NULL) {
        return;
    }
    p[0] = 'x';
    exit(1);
    free(p);
}
