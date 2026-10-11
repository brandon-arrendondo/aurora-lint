/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: PASS - A write through &p replaces the literal before p is written
 * through
 */

#include <stdlib.h>

void mark(void)
{
    char *p = "lit";
    char **pp = &p;
    *pp = malloc(4);
    if (p)
        p[0] = 0;
}
