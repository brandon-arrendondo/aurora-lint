/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - the call goes through a forward declaration that a misread earlier declaration leaves inside a block
 *
 * WSD comes from a header the scan does not read, so the parse misreads
 * the state object as a function and the file-scope declarations after it
 * as a block's. The forward declaration of grow_finish still names the
 * function the call reaches; it does not hide it.
 */
#include <stddef.h>
#include "config.h" /* defines WSD and NOINLINE; not part of the scan */

static WSD struct State {
    int mutex;
    long limit;
} state = { 0, 0 };

static NOINLINE void *grow_finish(void *p, size_t n);

void *grow(void *p, size_t n)
{
    if (p == NULL) {
        return NULL;
    }
    return grow_finish(p, n);
}

static NOINLINE void *grow_finish(void *p, size_t n)
{
    return n ? p : NULL;
}
