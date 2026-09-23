/*
 * Rule: INT32-C
 * Source: real-world
 * Status: FAIL - `val * 8` on an alias for a signed integer type is signed
 *         multiplication, exactly as it is when the type is spelled out.
 *
 * The rule walked the typedef chain to answer "is this unsigned?" but not to
 * answer "is this an integer at all": an alias whose own spelling carried no
 * `int`/`long`/`short` was classified `not_applicable`, so every operation on
 * it left the rule silently. Both functions below are the same arithmetic on
 * the same underlying `long long` as the spelled-out `probe_builtin` shape
 * the rule has always reported; the alias must not change the answer, at one
 * level or through a chain of them.
 */

#include <stdlib.h>

typedef long long offset_alias_t;
typedef offset_alias_t stamp_alias_t;

void scale_offset(const char *pos, offset_alias_t *out)
{
    offset_alias_t val = atoi(pos);
    *out = val * 8;
}

void scale_stamp(const char *pos, stamp_alias_t *out)
{
    stamp_alias_t val = atoi(pos);
    *out = val * 8;
}
