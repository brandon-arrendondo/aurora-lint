/*
 * Rule: INT32-C
 * Source: task 657 (seL4 delta-adjudication task 631)
 * Status: PASS - Should NOT trigger INT32-C violation
 *
 * seL4 typedefs `word_t` to `unsigned long`, then chains further aliases
 * (`paddr_t`, ...) onto `word_t` from a struct field declared through that
 * chain (`p_region_t.start`/`.end`). Subtracting two such fields to compute
 * a `memcpy`/`memset` size argument must not be flagged: unsigned wraparound
 * there is well-defined (INT30-C's concern, not INT32-C's), but recognizing
 * that requires walking the field's declared type through the full,
 * cross-file-shaped typedef chain rather than a one-level lookup.
 */
// sqc-test: prescan

#include <string.h>

typedef unsigned long word_t;
typedef word_t paddr_t;

typedef struct p_region {
    paddr_t start;
    paddr_t end;
} p_region_t;

void copy_region(p_region_t regions, void *dst, void *src) {
    memcpy(dst, src, regions.end - regions.start);
}

paddr_t region_size(paddr_t start, paddr_t end) {
    return end - start;
}

int main(void) {
    return 0;
}
