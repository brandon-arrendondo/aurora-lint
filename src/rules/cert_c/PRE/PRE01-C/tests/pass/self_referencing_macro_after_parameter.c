/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE01-C violation
 *
 * `A` and `B` expand to each other. The preprocessor leaves a name it is
 * already expanding as it is, so `A` never becomes a string literal or an
 * operator: what follows `x` is unknown, and with nothing after it `x` is
 * read as a declaration's type. Each macro is expanded once, so the wide
 * cycle is cheap to read.
 */

#define A B B B B B B B B B B B B
#define B A A A A A A A A A A A A
#define F(x) x A
