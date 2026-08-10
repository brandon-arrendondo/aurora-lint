/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: get_blob() is a borrowed-accessor function -- it returns a pointer
 * into another object's internal state, never a fresh allocation. Its body
 * contains no malloc/calloc/realloc/aligned_alloc call at all; the doc
 * comment merely *mentions* "malloc()" while explaining why no allocation
 * happens here. FunctionSummary's returns_allocation must not misread that
 * comment as evidence the function allocates (task 427). Modeled on
 * sqlite's real sqlite3_column_blob(), whose doc comment reads "might need
 * to call malloc() to expand the result of a zeroblob() expression".
 */

#include <stdlib.h>

struct row {
    const void *data;
};

const void *get_blob(struct row *r)
{
    const void *val;
    val = r->data;
    /* Even though there is no encoding conversion, expanding might
     * need to call malloc() to grow the backing store first.
     */
    return val;
}

void use_blob(struct row *r)
{
    const void *zRoot = get_blob(r);
    (void)zRoot;
    /* zRoot is borrowed from r; nothing to free here. */
}
