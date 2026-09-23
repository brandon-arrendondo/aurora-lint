/*
 * Rule: INT32-C
 * Source: real-world (valkey src/sds.c:508 `(len - curlen + 1)`,
 *         src/valkey-cli.c:9631 `(n1 - p)`, src/replication.c:3578
 *         `offset - replid - 1`, src/setproctitle.c:296 `SPT.end - SPT.base`,
 *         src/cluster_legacy.c:2150 `(sizeof(*x) * n)`)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: none of these memcpy/memmove/memset size arguments is signed
 *         integer arithmetic: size_t operands, a sizeof product, or a
 *         pointer difference (ptrdiff_t, bounded by the object both point
 *         into). The size-argument check's type gate looked only at a bare
 *         `binary_expression`, so a parenthesized expression or a pointer
 *         difference (typed "not_applicable", not "unsigned") still reached
 *         the report. The anonymous file-scope struct has no
 *         struct_field_types entry, so its pointer fields are read from the
 *         inline struct body.
 */

#include <string.h>
#include <stddef.h>

static struct {
    const char *arg0;
    char *base, *end;
} SPT;

void grow_zero(char *s, size_t curlen, size_t len)
{
    if (len <= curlen)
        return;
    memset(s + curlen, 0, (len - curlen + 1));
}

void copy_span(char *result, char *p, char *n1)
{
    memcpy(result, p, (n1 - p));
}

void copy_replid(char *dst, char *replid, char *offset)
{
    memcpy(dst, replid, offset - replid - 1);
}

void clear_title(void)
{
    memset(SPT.base, 0, SPT.end - SPT.base);
}

void drop_replica(void **replicas, size_t j, size_t num_replicas)
{
    size_t remaining = (num_replicas - j) - 1;
    memmove(replicas + j, replicas + (j + 1), (sizeof(*replicas) * remaining));
}
