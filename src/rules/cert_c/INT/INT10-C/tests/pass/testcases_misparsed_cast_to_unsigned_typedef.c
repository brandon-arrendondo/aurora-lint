/*
 * Rule: INT10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger INT10-C violation
 *
 * Regression test for task 675, from seL4 src/smp/lock.c:19:
 *
 *     assert(((seL4_Word)&big_kernel_lock) % EXCL_RES_GRANULE_SIZE == 0);
 *
 * tree-sitter-c cannot tell a cast from a bitwise AND without knowing whether
 * the parenthesized name is a type, and it does not consult a typedef table
 * here -- so `(seL4_Word)&x` comes back as a binary_expression whose left
 * operand is a parenthesized identifier, not a cast_expression. Task 657's
 * cast_expression handling therefore could not see this shape at all.
 *
 * The dividend is a cast to an unsigned typedef, so the remainder cannot be
 * negative. The divisor here is a plain signed parameter on purpose: a named
 * non-negative divisor would be suppressed by an unrelated path, which would
 * make this fixture pass whether or not the misparse is handled.
 *
 * Needs the prescan context: the typedef chain INT10-C resolves lives in
 * ProjectContext, which is built by the prescan, so without this marker the
 * chain is empty and the fixture would pass for the wrong reason.
 */


typedef unsigned long word_t;
typedef word_t my_word_t;

extern int lock_object;

int aligned_via_misparsed_cast(int granule)
{
    return ((my_word_t)&lock_object) % granule == 0;
}
