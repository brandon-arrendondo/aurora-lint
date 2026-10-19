/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the loop in the statement expression runs `*p` again after `p = NULL`, so a later iteration reads a null pointer even though the write comes after the dereference in the text
 */

#include <stddef.h>

char *get(void);

int f(int k)
{
    char *p;
    int s = 0;
    return (p = get()) && ({
        while (k--) {
            s += *p;
            p = NULL;
        }
        1;
    });
}
