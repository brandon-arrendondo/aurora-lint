/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A test speaks for a block only if its spelling still means the
 * object the block went into. A shadowing declaration, a reassignment or an
 * index that moved makes it another object, so the block is still held.
 */

#include <stdlib.h>
#include <string.h>

char *get(void);

int shadowed_in_an_inner_block(void)
{
    char *p = malloc(8); /* Expect: here */
    {
        char *p = get();
        if (p) {
            free(p);
            return 0;
        }
    }
    return -1; /* Expect: here */
}

int allocated_into_the_shadow(void)
{
    char *p = get();
    {
        char *p = malloc(8); /* Expect: here */
        (void)p;
    }
    if (p) {
        /* The inner block, leaked when its scope closed, is reported again at
           this return: the walk keeps one record per spelling. */
        return 0; /* Expect: here */
    }
    return -1; /* Expect: here */
}

int reassigned_before_the_test(void)
{
    char *p = malloc(8); /* Expect: here */
    p = strchr(p, 'x');
    if (p) {
        free(p);
        return 0;
    }
    return -1; /* Expect: here */
}

int index_moved_before_the_test(int i)
{
    char *a[4];
    a[i] = malloc(8); /* Expect: here */
    i++;
    if (a[i]) {
        free(a[i]);
        return 0;
    }
    return -1; /* Expect: here */
}

char *index_moved_before_the_return(int i)
{
    char *a[4];
    a[i] = malloc(8); /* Expect: here */
    i++;
    return a[i]; /* Expect: here */
}
