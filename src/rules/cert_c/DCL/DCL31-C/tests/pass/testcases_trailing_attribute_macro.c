/*
 * Rule: DCL31-C
 * Source: testcases
 * Status: PASS - A real explicit type followed by a GCC-style attribute
 * macro invocation (ALIGN(...), VISIBLE, SKIM_BSS) must not be flagged as
 * a missing type specifier.
 *
 * Task 650 (seL4 delta-adjudication): tree-sitter-c splits a declaration
 * like `pml4e_t arr[N] ALIGN(BIT(X)) VISIBLE;` into two `declaration`
 * nodes -- the real one (`pml4e_t arr[N]`) and a spurious second one for
 * the attribute tail (`ALIGN(BIT(X)) VISIBLE;`), parsed with `ALIGN(...)`
 * as a `macro_type_specifier` and `VISIBLE` as the declarator. Before the
 * fix, that second node had no recognized type-specifier child and was
 * flagged as implicit-int. Likewise a leading attribute macro before a
 * function definition's real type (`ALIGN(L1_CACHE_LINE_SIZE)\nvoid
 * VISIBLE f(...)`) splits off a bogus `ALIGN(...) void;` declaration the
 * same way.
 */

typedef struct { int x; } pml4e_t;
typedef unsigned long word_t;

#define BIT(n) (1UL << (n))
#define ALIGN(n) __attribute__((aligned(n)))
#define VISIBLE __attribute__((externally_visible))

pml4e_t x64KSKernelPML4[BIT(9)] ALIGN(BIT(12)) VISIBLE;

ALIGN(64)
void VISIBLE c_handle_fastpath_call(word_t cptr, word_t msgInfo)
{
    (void)cptr;
    (void)msgInfo;
}
