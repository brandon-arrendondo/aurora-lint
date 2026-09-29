/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * inner() zeroes the count it reports through `*pn` before it knows it,
 * the way a byte-count out-parameter usually is. That stores an integer,
 * not a null pointer, and a store through `pn` says nothing about `pn`
 * itself, so the caller's `pn` is as non-null after the call as before.
 * The same holds for a pointer-to-pointer handed on as it is: lookup()
 * may leave NULL in `*out`, not in `out`.
 */
#include <stddef.h>

struct handle { int fd; };
static struct handle the_handle;

int inner(const char *buf, size_t len, size_t *pn) {
    *pn = 0;
    if (!buf)
        return -1;
    *pn = len;
    return 0;
}

int outer(const char *buf, size_t len, size_t *pn) {
    inner(buf, len, pn);
    return (int)*pn;
}

void lookup(int key, struct handle **out) {
    if (key == 1)
        *out = &the_handle;
    else
        *out = 0;
}

int found(int key, struct handle **out) {
    lookup(key, out);
    return *out != 0;
}
