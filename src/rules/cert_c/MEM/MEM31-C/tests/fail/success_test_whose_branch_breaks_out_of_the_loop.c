/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A success test inside a loop says the name is empty only on
 * the code below it. A branch that breaks or continues takes the block on
 * out of the loop, so the return after the loop still reports it.
 */

#include <stdlib.h>

void use(char *p);
int more(void);

int branch_breaks(void)
{
    char *p = NULL;
    while (more()) {
        p = malloc(8); /* Expect: here */
        if (p) {
            use(p);
            break;
        }
    }
    return 0; /* Expect: here */
}

int branch_breaks_an_endless_loop(void)
{
    char *p = NULL;
    for (;;) {
        p = malloc(8); /* Expect: here */
        if (p) {
            use(p);
            break;
        }
    }
    return 0; /* Expect: here */
}

int branch_continues(void)
{
    char *p = NULL;
    while (more()) {
        p = malloc(8); /* Expect: here */
        if (p) {
            use(p);
            continue;
        }
    }
    return 0; /* Expect: here */
}
