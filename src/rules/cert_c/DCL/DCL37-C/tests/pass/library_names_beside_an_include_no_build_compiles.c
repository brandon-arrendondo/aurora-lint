/*
 * Rule: DCL37-C
 * Status: PASS - <stdbool.h> appears only where no build of this C file
 * includes it: under `#if 0`, in a `__cplusplus` arm and in a comment. So
 * `false` and `true` are not reserved here.
 */

#if 0
#include <stdbool.h>
#endif

#ifdef __cplusplus
#include <stdbool.h>
#endif

/*
#include <stdbool.h>
*/

enum answer { false, true };
