/*
 * Rule: MEM02-C
 * Source: regression (task 405)
 * Status: PASS - Should NOT trigger MEM02-C violation
 * Description: A same-named pointer variable declared with different types
 * in two different functions, each correctly cast to its own function's
 * type, must not produce a false positive. Without per-function scoping,
 * the file-wide "declared type per variable name" map would let the second
 * function's declaration of "p" overwrite the first function's entry,
 * making correct_cast_first_function() incorrectly compare its cast against
 * the second function's (unrelated) type for "p".
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

void correct_cast_first_function(void) {
    gadget *p;

    p = (gadget *)malloc(sizeof(gadget)); /* Compliant: correct cast for this function's p */
}

void correct_cast_second_function(void) {
    widget *p;

    p = (widget *)malloc(sizeof(widget)); /* Compliant: correct cast for this function's p */
}
