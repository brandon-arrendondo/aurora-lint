/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A helper that frees `p->b.c` releases that field of what it
 * is handed, under either member operator: `a.b.c` through `&a`, and
 * `pa->b.c` through `pa`. A sibling field the helper never frees stays
 * leaked, reported where it is allocated and where the function returns.
 * Expect: count=2
 */
#include <stdlib.h>
#include <string.h>

struct in {
    char *c;
    char *d;
};

struct s {
    struct in b;
};

static void free_nested(struct s *p)
{
    free(p->b.c);
}

int through_address(void)
{
    struct s a;

    a.b.c = strdup("x");
    a.b.d = strdup("y"); /* Expect: here */
    free_nested(&a);
    return 0; /* Expect: here */
}

int through_pointer(struct s *pa)
{
    pa->b.c = strdup("x");
    free_nested(pa);
    return 0;
}
