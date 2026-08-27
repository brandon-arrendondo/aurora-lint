/*
 * Rule: MSC12-C
 * Status: PASS - An "empty" if/else branch whose only content is a
 * structured verification-annotation comment (seL4's Isabelle/HOL
 * AUXUPD/GHOSTUPD proof-hint convention) is not dead code -- the comment
 * IS the branch's entire purpose, consumed by a separate proof build
 * invisible to a plain C compile. Modeled on
 * src/arch/x86/64/object/objecttype.c:191/209/233/239 and
 * src/arch/riscv/object/objecttype.c:205 in seL4 (task 476). Scoped to
 * this specific tag convention, not any comment -- see
 * testcases_empty_if_body.c / testcases_empty_else_body.c for the
 * bare-comment case, which must still be flagged.
 */

void retype_region(int is_large) {
    if (is_large) {
        /** AUXUPD: "(True, ptr_retyps 2
              (Ptr ptr :: x86_large_page_C ptr) o addrFromPPtr)" */
        /** GHOSTUPD: "(True, gs_new_frames vmpage_size.X64LargePage
              (ptr_val ptr && ~~ mask 21) 21)" */
    } else {
        /** AUXUPD: "(True, ptr_retyps 1
              (Ptr ptr :: x86_small_page_C ptr) o addrFromPPtr)" */
    }
}
