/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A helper that frees a field off what it is handed releases
 * that field of whatever its argument names: `&a.b` hands it `a.b`,
 * `&arr[0]` hands it `arr[0]`, and a helper handed `&a` that frees
 * `p->b.c` releases `a.b.c`.
 */
#include <stdlib.h>
#include <string.h>

struct in {
    char *c;
};

struct s {
    char *x;
    struct in b;
};

static void free_in(struct in *q)
{
    free(q->c);
}

static void free_nested(struct s *p)
{
    free(p->b.c);
}

int member_address(void)
{
    struct s a;

    a.b.c = strdup("x");
    if (a.b.c == NULL)
        return -1;
    free_in(&a.b);
    return 0;
}

int element_address(void)
{
    struct in arr[2];

    arr[0].c = strdup("x");
    if (arr[0].c == NULL)
        return -1;
    free_in(&arr[0]);
    return 0;
}

int nested_field(void)
{
    struct s a;

    a.b.c = strdup("x");
    if (a.b.c == NULL)
        return -1;
    free_nested(&a);
    return 0;
}
