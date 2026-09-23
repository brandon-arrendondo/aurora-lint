/*
 * Rule: EXP13-C
 * Source: real-world (valkey src/module.c:13497)
 * Status: PASS - Should NOT trigger EXP13-C violation
 *
 * The `<` and `>` delimiting a header name in __has_include() are not
 * relational operators, so there is no chained comparison here. tree-sitter
 * has no preprocessor: when it cannot place this directive it absorbs it into
 * an ERROR node and the header name reparses as `a < dlfcn.h > ...`.
 * See ADR-0008.
 */

int f(void)
{
#if (defined(__GLIBC__) || defined(__FreeBSD__)) && !defined(NO_SAN) && __has_include(<dlfcn.h>)
    return 1;
#endif
    return 0;
}
