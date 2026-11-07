/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: close releases a descriptor. Handed a block of memory it frees
 * nothing, so the block still leaks.
 */

#include <stdlib.h>

struct conn;

extern int close(struct conn *c);

int conn_closed(void)
{
    struct conn *c = malloc(8); /* Expect: here */
    close(c);
    return 0; /* Expect: here */
}

struct holder {
    struct conn *a;
};

int field_closed(void)
{
    struct holder l;
    l.a = malloc(8); /* Expect: here */
    close(l.a);
    return 0; /* Expect: here */
}
