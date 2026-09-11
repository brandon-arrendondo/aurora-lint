/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `if (p) free(p);` with no braces is the standard cleanup
 * idiom, and it is a double free here because `p` was freed two lines
 * above. The walk once visited an `if`'s consequence only when it was a
 * `compound_statement`, so a braceless body was never seen: this free
 * neither counted for double-free detection nor for the leak sweep, while
 * the braced spelling `if (p) { free(p); }` did both. The consequence is
 * whatever statement follows the condition.
 */

#include <stdlib.h>

void release_twice(char *p) {
    free(p);
    if (p) free(p);
}
