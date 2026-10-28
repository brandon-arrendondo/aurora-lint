/*
 * Rule: DCL00-C
 * Source: aurora-lint
 * Status: FAIL - a local reuses the name of a storage-class macro the file
 * has #undef'd
 * Expect: count=1
 *
 * Past the #undef, STATIC is no macro but an ordinary identifier, so the
 * local named STATIC is initialized and never modified.
 */

#define STATIC static

typedef int myint;

STATIC myint helper(void) {
  return 2;
}

#undef STATIC

int scaled(int v) {
  int STATIC = v * helper(); /* Expect: here */
  return STATIC + 1;
}
