/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE01-C violation
 *
 * A parameter followed by a typedef name the standard library declares is
 * part of a type name (a qualifier or storage class here), even when the
 * header that declares it is not read: `uint32_t` and `size_t` are types
 * by their names. Each last parameter closes a parameter list.
 */

#define TAKE_U32(qual, name) void take_u32(qual uint32_t name)
#define TAKE_SIZE(x, n) void take_size(x size_t n)

TAKE_U32(const, value);
TAKE_SIZE(const, count);
