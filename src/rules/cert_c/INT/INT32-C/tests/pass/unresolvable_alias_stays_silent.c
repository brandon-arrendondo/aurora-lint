/*
 * Rule: INT32-C
 * Source: task 1287
 * Status: PASS - the alias's chain reaches a macro, not a type, so nothing
 *         here is known to be signed and the rule reports nothing.
 *
 * This is curl's `curl_off_t` shape (`typedef CURL_TYPEOF_CURL_OFF_T
 * curl_off_t;`, the macro defined differently in eight `#if` branches) and,
 * for the same reason, glibc's `time_t`: the chain the scan can see does not
 * end at an arithmetic type. Resolving the chain (the sibling FAIL fixture)
 * is the fix; guessing from the alias's *name* when the chain runs out is
 * what ADR-0006 forbids, so the honest answer here is silence.
 */

#include <stdlib.h>

#define OPAQUE_TYPEOF long long
typedef OPAQUE_TYPEOF opaque_alias_t;

void scale_opaque(const char *pos, opaque_alias_t *out)
{
    opaque_alias_t val = atoi(pos);
    *out = val * 8;
}
