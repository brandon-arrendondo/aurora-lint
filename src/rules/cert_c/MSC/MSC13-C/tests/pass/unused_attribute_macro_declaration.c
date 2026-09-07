/*
 * Rule: MSC13-C
 * Source: seL4 src/arch/arm/64/kernel/vspace.c, src/arch/arm/32/kernel/vspace.c,
 *         src/arch/x86/32/kernel/vspace.c (task 964)
 * Status: PASS - Should NOT trigger MSC13-C violations
 *
 * `__attribute__((unused))`, usually behind a project macro like seL4's
 * `UNUSED`, is the author declaring in the one place C provides for it that
 * this variable may legitimately go unread. MSC13-C exists to respect that
 * intent, so a declaration carrying the annotation is not reported.
 *
 * The macro also breaks the parse: aurora-lint has no preprocessor, so a bare
 * `UNUSED` sitting where a type or declarator belongs is absorbed into the
 * declaration and the recovered parse names the wrong token -- reporting
 * "Variable 'pptr_t' is initialized but never read" for `UNUSED pptr_t
 * vaddr = ...`, and "Variable 'UNUSED' is declared but never used" for
 * `pptr_t UNUSED pteS2;`. Keying the suppression on the declaration rather
 * than on the recovered name is deliberate: the name is untrustworthy here,
 * the annotation's presence is not. The macro is resolved through its
 * replacement text, never through the spelling `UNUSED`.
 */

#define UNUSED __attribute__((unused))

typedef unsigned long pptr_t;
typedef unsigned long word_t;
typedef int exception_t;

extern exception_t cteDelete(int slot, int exposed);

/* Attribute macro BEFORE the declarator. */
void before_declarator(void) {
    UNUSED pptr_t vaddr = 0x1000;
}

/* Attribute macro BETWEEN the type and the declarator. */
void between_type_and_declarator(void) {
    pptr_t UNUSED pteS2;
    unsigned int UNUSED i;
}

/* Attribute macro AFTER the declarator, the trailing-attribute form
 * (seL4 src/object/objecttype.c:602, task 1019). Here the parser strands the
 * macro rather than the variable, so the parse-repair pass blanks the macro
 * itself and the annotation would be gone before this rule ever runs -- it
 * survives only as the marker the pass leaves in its place. */
void after_declarator(void) {
    word_t totalObjectSize UNUSED;
}

/* The attribute written out, with no macro in the way. */
void spelled_out(void) {
    __attribute__((unused)) int direct = 7;
    int also_direct __attribute__((__unused__));
}
