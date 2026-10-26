/*
 * Rule: PRE01-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE01-C violation
 *
 * Each parameter use sits before a keyword where parentheses would not
 * compile:
 * - before an attribute, a storage class, a function specifier, an
 *   alignment specifier or an asm label, as part of a declaration
 *   (`T __attribute__((unused)) name`, `attr static T`, `ret inline`,
 *   `vis extern`, `ret _Noreturn`, `T _Alignas(8)`, `x __asm__("sym")`);
 * - as the body of a do/while, or the first statement of an if/else,
 *   whose argument is a statement (`do body while (0)`, `if (1) stmt else`);
 * - as the operator before `sizeof` or `_Alignof`, which start operands,
 *   also when a parameter follows `sizeof` (`1 op sizeof x`).
 */

#define UNUSED_LOCAL(T) T __attribute__((unused)) unused_local = 0
#define STATIC_COUNTER(attr, T) attr static T counter_static = 0
#define INLINE_FN(ret) static ret inline twice(int v) { return 2 * v; }
#define EXTERN_INT(vis) vis extern int shared_value
#define NORETURN_FN(ret) ret _Noreturn void stop(void)
#define ALIGNED(T) T _Alignas(8) aligned_value
#define ASM_LABEL(x) extern int x __asm__("sym")
#define ONCE(body) do body while (0)
#define EITHER(stmt) if (1) stmt else ;
#define PLUS_SIZE(op) (1 op sizeof(int))
#define PLUS_SIZE_OF(op, x) (1 op sizeof x)
#define PLUS_ALIGN(op) (2 op _Alignof(int))
