/*
 * Rule: MSC17-C
 * Source: lua lparser.c (task 632)
 * Status: PASS - Should NOT trigger MSC17-C violation
 *
 * A genuine fallthrough marker comment can itself sit right after the
 * closing #endif of a preprocessor-guarded case (not just inside it),
 * documenting the fallthrough of the case *before* the #ifdef block. The
 * #endif-annotation-comment fix (task_632_endif_comment_and_noreturn_marker)
 * must only drop a comment in that position when it is NOT itself a marker.
 */

void f(int t) {
  switch (t) {
  case 1:
    break;
#if COMPAT_GLOBAL
  case 2: {
    do_thing();
  }
#endif
  /* FALLTHROUGH */
  default:
    do_default();
    break;
  }
}
