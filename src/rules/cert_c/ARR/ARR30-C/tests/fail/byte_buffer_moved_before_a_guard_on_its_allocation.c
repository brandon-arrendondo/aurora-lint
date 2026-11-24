/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The allocation size bounds a pointer that no longer points at its start
 * Expect: count=4
 *
 * Each buffer is allocated with N + 1 bytes and the index is checked
 * against N, but by the access the pointer may have moved 40 bytes in: by
 * a callee given its address, on the allocation's own line, around a
 * backward goto, or through another pointer to it.
 */
#include <stdlib.h>
#define N 64
extern size_t next(void);
extern int more(void);
extern void skip(char **);

void through_a_callee(void)
{
    size_t i = next();
    char *p = malloc(N + 1);
    if (p == NULL)
        return;
    skip(&p);
    if (i >= N)
        return;
    p[i] = 0; /* Expect: here */
}

void on_the_same_line(void)
{
    size_t i = next();
    char *p = malloc(N + 1); p += 40;
    if (p == NULL)
        return;
    if (i >= N)
        return;
    p[i] = 0; /* Expect: here */
}

void around_a_goto(void)
{
    size_t i;
    char *p = malloc(N + 1);
    if (p == NULL)
        return;
again:
    i = next();
    if (i >= N)
        return;
    p[i] = 0; /* Expect: here */
    p += 40;
    if (more())
        goto again;
}

void through_another_pointer(void)
{
    size_t i = next();
    char *p = malloc(N + 1);
    char **pp = &p;
    if (p == NULL)
        return;
    *pp += 40;
    if (i >= N)
        return;
    p[i] = 0; /* Expect: here */
}
