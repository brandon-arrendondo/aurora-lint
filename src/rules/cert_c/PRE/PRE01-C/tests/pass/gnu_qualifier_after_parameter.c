/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE01-C violation
 *
 * GCC's alternate spellings of the qualifiers continue a type name like
 * the standard ones, so a parameter before one is part of the type and
 * cannot take parentheses. Each last parameter closes a parameter list.
 */

#define TAKE_RESTRICT(T, p) void take_restrict(T __restrict p)
#define TAKE_CONST(T, n) void take_const(T __const n)
#define TAKE_VOLATILE(T, n) void take_volatile(T __volatile__ n)

TAKE_RESTRICT(char *, buffer);
TAKE_CONST(int, count);
TAKE_VOLATILE(int, flag);
