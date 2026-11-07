/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A success test whose branch jumps away says the name is empty
 * on the code below it, until an allocation there fills it again. The new
 * block is reported where it leaks, whether the branch freed the old one or
 * only used it.
 */

#include <stdlib.h>

void use(char *p);

int branch_freed_then_jumped(void)
{
    char *p = malloc(8);
    if (p) {
        free(p);
        goto out;
    }
    p = malloc(8);
    return 1; /* Expect: here */
out:
    return 0;
}

int branch_used_then_jumped(void)
{
    char *p = malloc(8);
    if (p) {
        use(p);
        goto out; /* Expect: here */
    }
    p = malloc(8); /* Expect: here */
    return 1; /* Expect: here */
out:
    return 0; /* Expect: here */
}

struct holder {
    char *buf;
};

int field_freed_then_jumped(void)
{
    struct holder h;
    h.buf = malloc(8);
    if (h.buf) {
        free(h.buf);
        goto out;
    }
    h.buf = malloc(8);
    return 1; /* Expect: here */
out:
    return 0;
}
