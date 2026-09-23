/*
 * Rule: DCL05-C
 * Source: real-world (mbedtls library/ecp.c, pure-ftpd src/bsd-glob.c)
 * Status: PASS - Should NOT trigger DCL05-C violation
 *
 * A single function-pointer parameter is the universal C callback idiom.
 * CERT exempts function pointer types from this recommendation; the only
 * declarations it calls hard to read nest one function type inside another.
 */

#include <stddef.h>

typedef struct glob_s { int gl_pathc; } glob_t;

static int ecp_randomize_jac(const int *grp, int *pt,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    unsigned char buf[8];
    (void)grp;
    (void)pt;
    return f_rng(p_rng, buf, sizeof buf);
}

/* Unnamed function-pointer parameter in a prototype. */
int glob(const char *, int, int (*)(const char *, int), glob_t *);

void qsort_wrapper(void *base, size_t n, size_t sz,
                   int (*cmp)(const void *, const void *))
{
    (void)base;
    (void)n;
    (void)sz;
    (void)cmp;
}

/* A function returning a plain pointer, taking a callback. */
void *entry_defrag(void *e, void *(*defragfn)(void *))
{
    return defragfn(e);
}
