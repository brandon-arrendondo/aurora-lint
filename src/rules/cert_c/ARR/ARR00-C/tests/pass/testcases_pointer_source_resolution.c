/*
 * Rule: ARR00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR00-C violation
 *
 * Regression test for task 752: two text-scan bugs in
 * find_pointer_source_array_recursive, both taken from real hostap findings
 * that were adjudicated false positives.
 *
 * 1. No identifier-boundary check. The resolver did
 *    preceding_text.rfind("pos = "), which matches inside 'hpos = hash;', so
 *    every 'pos' in the function was attributed to the array 'hash' and the
 *    subtraction below looked like it spanned two different arrays.
 *
 * 2. A chained assignment never collapsed to one base. 'pos = hs_start =
 *    verify_data;' resolved 'pos' to the intermediate 'hs_start' -- the
 *    recursive resolve only searches text to the LEFT of its own match, where
 *    the chain's real right-hand side never appears -- so 'pos' and 'hs_start'
 *    disagreed about their base despite being the same pointer.
 */

#include <stddef.h>

/* Bug 1: 'hpos' must not be read as an assignment to 'pos'. */
static size_t remaining_bytes(unsigned char *hash, unsigned char *buf,
                              size_t len)
{
    unsigned char *pos = buf;
    unsigned char *end = pos + len;
    unsigned char *hpos = hash;

    *hpos = 0;

    /* Both operands are derived from 'buf'. */
    return (size_t)(end - pos);
}

/* Bug 2: a chained assignment gives both pointers the same base. */
static size_t handshake_len(unsigned char *verify_data, size_t len)
{
    unsigned char *pos, *hs_start;

    pos = hs_start = verify_data;
    pos += len;

    /* Both operands are derived from 'verify_data'. */
    return (size_t)(pos - hs_start);
}

int arr00_pointer_source_resolution(unsigned char *hash, unsigned char *buf,
                                    size_t len)
{
    return (int)(remaining_bytes(hash, buf, len) + handshake_len(buf, len));
}
