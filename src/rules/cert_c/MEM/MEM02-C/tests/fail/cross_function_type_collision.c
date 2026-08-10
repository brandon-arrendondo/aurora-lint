/*
 * Rule: MEM02-C
 * Source: regression (task 405)
 * Status: FAIL - Should trigger MEM02-C violation
 * Description: A same-named pointer variable declared with different types
 * in two different functions must not share a single file-wide "declared
 * type per variable name" map. Without per-function scoping, whichever
 * function's declaration of "p" is processed last in the file wins the
 * shared entry, masking the real cast mismatch below in
 * mismatched_cast_masked_by_other_function() (it would incorrectly compare
 * against "gadget", the *other* function's type for "p", and see no
 * mismatch).
 */

#include <stdlib.h>

typedef struct gadget gadget;
struct gadget {
  int i;
  double d;
};

typedef struct widget widget;
struct widget {
  char c[10];
  int i;
  double d;
};

void mismatched_cast_masked_by_other_function(void) {
    widget *p;

    p = (gadget *)malloc(sizeof(gadget)); /* Violation: p is widget*, cast is gadget* */
}

void other_function_same_var_name(void) {
    gadget *p;

    p = (gadget *)malloc(sizeof(gadget)); /* Compliant: correct cast for this function's p */
}
