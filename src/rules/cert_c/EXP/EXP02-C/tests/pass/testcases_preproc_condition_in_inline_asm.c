/*
 * Rule: EXP02-C
 * Source: real-world site 5 -- real shapes from mbedtls
 *   library/constant_time_impl.h:293 and sel4 src/arch/x86/64/c_traps.c:308,
 *   353, 410 (all four the same construct)
 * Status: PASS - Should NOT trigger EXP02-C violation
 *
 * Same misfire as testcases_preproc_condition_feature_test.c, reached by a
 * different route. Here the `#if` opens inside an unclosed `asm volatile(`,
 * so tree-sitter cannot place the directive: it lands in an ERROR node and
 * `defined(__thumb2__)` reparses as an ordinary call_expression with no
 * preproc_if above it. The condition-based exemption cannot see this one --
 * there is no preproc_if to find -- so the `defined` operator is recognized
 * on its own.
 *
 * paren_preproc_guard would normally repair a preprocessor conditional
 * opening inside an unclosed paren, and deliberately declines here: the block
 * has an `#else`, and blanking one arm of a two-armed block would silently
 * pick a side of the expression.
 */
void asm_guarded(unsigned x, unsigned y)
{
    unsigned s1;
    asm volatile (
        ".syntax unified                                          \n\t"
#if defined(__thumb__) && !defined(__thumb2__)
        "movs     %[s1], %[x]                                     \n\t"
        "eors     %[s1], %[s1], %[y]                              \n\t"
#else
        "eor      %[s1], %[x], %[y]                               \n\t"
#endif
        : [s1] "=&r" (s1)
        : [x] "r" (x), [y] "r" (y)
    );
}
