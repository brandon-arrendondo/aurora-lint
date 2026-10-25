/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE01-C violation
 *
 * Each parameter use sits in a type or a string concatenation, where
 * parentheses would not compile:
 * - before a type keyword or a typedef name (`qual int`, `qual counter_t`);
 * - before a macro that expands to string literals, directly or through
 *   another (`FMT_U64` is `"%" PRI64 "u"`, and `PRI64` is `"ll"`);
 * - before an invocation of a macro that expands to its own argument, as
 *   a format table does (`FMT_2(fmt, value)` is `fmt ""`), or of one the
 *   macro tables cannot read (`FMT_4` is variadic);
 * - as the operator between two operands (`op` in `INT_OP`);
 * - as a cast's type name with a qualifier before it (`(const T *)0`).
 */

#include <stdio.h>
#include <stddef.h>

typedef unsigned counter_t;

#define PRI64 "ll"
#define FMT_U64 "%" PRI64 "u"
#define DECLARE_QUALIFIED(qual) qual int first = 0
#define DECLARE_COUNTER(qual) qual counter_t second = 0
#define WITH_U64(fmt) fmt FMT_U64
#define CONST_NULL_OF(T) ((const T *)0)
#define FMT_2(fmt, value) fmt ""
#define FMT_4(fmt, value, ...) fmt FMT_2(__VA_ARGS__)
#define FMT_6(fmt, value, ...) fmt FMT_4(__VA_ARGS__)
#define CAST_U(i) ((unsigned)(i))
#define CAST_S(i) ((int)(i))
#define INT_OP(op, v1, v2) CAST_S(CAST_U(v1) op CAST_U(v2))

DECLARE_QUALIFIED(static);
DECLARE_COUNTER(static);

int main(void) {
    printf(WITH_U64("value: ") "\n", 1ULL);
    printf(FMT_6("%d", 1, " %d", 2, " %d\n", 3), 1, 2, 3);
    return INT_OP(+, 1, 2) + first + (int)second + (CONST_NULL_OF(char) == NULL);
}
