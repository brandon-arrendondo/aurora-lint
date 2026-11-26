/*
 * Rule: MEM31-C
 * Source: synthetic
 * Status: PASS - A freed pointer and another name are both set by a chain that ends in no name
 *
 * Each function frees `b` and then assigns both `a` and `b` in one chain
 * whose last value is not a name: a null pointer, a cast null pointer, or
 * arithmetic. Neither name then holds an allocation, so nothing leaks,
 * just as when the two assignments are written as separate statements.
 */
#include <stdlib.h>

void chain_ends_in_null(void)
{
    char *a, *b = malloc(4);
    if (!b)
        return;
    free(b);
    a = b = NULL;
    (void)a;
}

void chain_ends_in_a_cast_null(void)
{
    char *a, *b = malloc(4);
    if (!b)
        return;
    free(b);
    a = b = (char *)0;
    (void)a;
}

void chain_ends_in_arithmetic(char *x)
{
    char *a, *b = malloc(4);
    if (!b)
        return;
    free(b);
    a = b = x + 1;
    (void)a;
}
