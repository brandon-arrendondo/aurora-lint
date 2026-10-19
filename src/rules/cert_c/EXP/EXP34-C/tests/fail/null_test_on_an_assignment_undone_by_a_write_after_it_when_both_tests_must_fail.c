/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in `(((p = get()) == NULL || (p = NULL, 0)) && (p = other()) == NULL) || *p`, when the first test lets the second be skipped, the comma after it has stored NULL in `p`, so `*p` reads a null pointer
 */

#include <stddef.h>

char *get(void);
char *other(void);

int f(void)
{
    char *p;
    return (((p = get()) == NULL || (p = NULL, 0)) && (p = other()) == NULL) || *p;
}
