/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: FAIL
 * Reason: The init/free pairing (task 1235) only reclassifies the paired
 *         `X_free(obj)` as a contents-free. It must not hide a real double
 *         free of the object afterwards, nor a name-shaped free with no init
 *         partner, nor a paired free applied to an object already released.
 */

#include <stdlib.h>

typedef struct { void *pk; } crt_t;
void lib_crt_init(crt_t *crt);
void lib_crt_free(crt_t *crt);
void other_free(void *p);

void real_double_free_after_pair(void)
{
    crt_t *p = malloc(sizeof(*p));
    lib_crt_init(p);
    lib_crt_free(p);
    free(p);
    free(p);            /* double free */
}

void no_init_partner(void)
{
    char *q = malloc(4);
    other_free(q);      /* name-shaped free, no `other_init(q)` seen */
    free(q);            /* double free */
}

void paired_free_on_released_object(void)
{
    crt_t *p = malloc(sizeof(*p));
    lib_crt_init(p);
    free(p);
    lib_crt_free(p);    /* use after free: contents-free of a freed object */
}
