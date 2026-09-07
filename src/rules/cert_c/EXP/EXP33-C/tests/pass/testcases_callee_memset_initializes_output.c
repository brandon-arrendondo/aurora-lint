/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. A callee whose whole
 * initialization of its output parameter is a memory-writing library call
 * writes it just as surely as an assignment does, but carries no assignment
 * operator for the summary's write detectors to find -- so the parameter never
 * entered `modifies_params` and every caller read the variable as
 * uninitialized. Modelled on hostap's `ieee802_11_parse_elems`, which is
 * `os_memset(elems, 0, sizeof(*elems))` plus a forward, and had 65 callers
 * flagged (task 1026).
 *
 * `os_memset` is declared, not defined, on purpose: the credit has to come
 * from the suffix matcher resolving the name to `memset`, not from a summary
 * of a local body.
 */
#include <stdio.h>
#include <stddef.h>

struct elems {
    int a;
    int b;
};

extern void os_memset(void *dst, int c, size_t n);

/* The ONLY write through `e` is the library call. */
static int parse_elems(const char *p, size_t len, struct elems *e)
{
    os_memset(e, 0, sizeof(*e));
    return (p != NULL && len > 0) ? 0 : -1;
}

void caller(const char *p, size_t len)
{
    struct elems elems;

    if (parse_elems(p, len, &elems) < 0)
        return;
    printf("%d %d\n", elems.a, elems.b);
}
