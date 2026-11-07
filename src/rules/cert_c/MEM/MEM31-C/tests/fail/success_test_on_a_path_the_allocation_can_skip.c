/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A success test speaks for the code below it only on the paths
 * that reach the test. Where an enclosing if, an else or a loop lets a path
 * from the allocation skip the test, the block is still held below it.
 */

#include <stdlib.h>

void use(char *p);

int test_inside_an_if(int c)
{
    char *p = malloc(8); /* Expect: here */
    if (c) {
        if (p) {
            free(p);
            return 0;
        }
    }
    return -1; /* Expect: here */
}

int test_inside_a_for(int n)
{
    char *p = malloc(8); /* Expect: here */
    for (int i = 0; i < n; i++) {
        if (p) {
            free(p);
            return 0;
        }
    }
    return 1; /* Expect: here */
}

int test_inside_a_while(int n)
{
    char *p = malloc(8); /* Expect: here */
    while (n-- > 0) {
        if (p) {
            free(p);
            return 0;
        }
    }
    return 1; /* Expect: here */
}

int test_in_an_else(int c)
{
    char *p = malloc(8); /* Expect: here */
    if (c) {
        use(p);
    } else if (p) {
        free(p);
        return 0;
    }
    return -1; /* Expect: here */
}

int jumping_test_inside_an_if(int c)
{
    char *p = malloc(8);
    if (c) {
        if (p) {
            free(p);
            goto out;
        }
    }
    return -1; /* Expect: here */
out:
    return 0;
}
