/*
 * Rule: INT32-C
 * Source: real-world (valkey src/replication.c:2772 `lastbytes + rem`,
 *         src/valkey-cli.c:9025 `obuf + obuf_pos`, src/zmalloc.c:898
 *         `line + flen`)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: each sum is a local ARRAY plus an offset -- pointer arithmetic,
 *         ARR30-C's concern, not a signed integer overflow. An earlier fix gated
 *         this for `char *` pointers, but the type map spells an array by
 *         its element type ("char"), so the array form slipped through as
 *         "Signed integer addition". The gate now resolves the occurrence to
 *         its declarator (ADR-0006) and reads the array declarator directly.
 */

#include <string.h>
#include <stdlib.h>

long parse_field(const char *flen_src, int rem, int nread, const char *buf)
{
    char lastbytes[40];
    char line[1024];
    int flen = (int)strlen(flen_src);

    memcpy(lastbytes + rem, buf, (size_t)nread);
    return strtol(line + flen, NULL, 10);
}
