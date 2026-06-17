/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: The manual-review heuristic for array-indexing function-like macros
 *         (check_macro_invocation) must fire ONLY when the macro is invoked on a
 *         buffer ARR30 actually tracks. Here the macro `AT(p,i)` is invoked on a
 *         call-result expression (`get_buf()`), which is not a tracked buffer
 *         name, so there is nothing to bounds-reason about and the call must not
 *         be flagged. The former condition `involves_buffer || !args.is_empty()`
 *         flagged every array-indexing macro call regardless of any tracked
 *         buffer (pure noise); migrating ARR30 onto the shared cross-region
 *         macro collector (task 186) exposed many more such macros, so this
 *         guard is what keeps the migration a precision win. The genuine
 *         out-of-bounds-on-a-tracked-buffer case still flags
 *         (see tests/fail/testcases_macro_over.c).
 */

#include <stddef.h>

#define AT(p, i) ((p)[i])

extern unsigned char *get_buf(void);

unsigned pick(void) {
    /* macro arg is a call-result expression, not a tracked buffer name */
    unsigned a = AT(get_buf(), 2);
    return a;
}
