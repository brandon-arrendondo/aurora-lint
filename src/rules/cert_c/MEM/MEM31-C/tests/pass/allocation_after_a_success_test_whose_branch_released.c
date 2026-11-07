/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should not trigger MEM31-C violation
 * Description: Below a success test whose branch returned, the name is empty,
 * so a new allocation into it overwrites nothing, and it leaks only if it is
 * not released itself.
 */

#include <stdlib.h>

int filled_again_and_released(void)
{
    char *p = malloc(8);
    if (p != NULL) {
        free(p);
        return 0;
    }
    p = malloc(8);
    free(p);
    return 1;
}
