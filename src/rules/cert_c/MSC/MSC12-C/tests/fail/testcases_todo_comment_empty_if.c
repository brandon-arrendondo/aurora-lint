/*
 * Rule: MSC12-C
 * Status: FAIL - An empty if body whose only content is a TODO/FIXME/NOTE
 * marker is still dead code and should be flagged, unlike the seL4
 * AUXUPD/GHOSTUPD verification-annotation convention (task 476). Guards
 * against widening is_verification_annotation_comment's tag match beyond
 * its explicit allowlist to any ALL_CAPS-word-plus-colon comment, which
 * would wrongly exempt this case.
 */

void f(int x) {
    if (x > 0) {
        /** TODO: implement this */
    }
}
