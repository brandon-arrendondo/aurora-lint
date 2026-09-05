/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: `typedef struct Underlying Alias;` has to resolve, or a member
 *         reached through the alias falls back to naming storage. Distilled
 *         from sqlite vdbe.c, where `pOut->z` vs `pC->aRow` fired because
 *         vdbe.h spells the type `Mem` while the fields are filed under
 *         `sqlite3_value` -- only ONE side failed to resolve, since
 *         `VdbeCursor`'s alias and struct name are the same string.
 */

struct sqlite3_value {
    char *z;
    int n;
};
typedef struct sqlite3_value Mem;

struct VdbeCursor {
    char *aRow;
    int nRow;
};
typedef struct VdbeCursor VdbeCursor;

int overlaps(Mem *pOut, VdbeCursor *pC)
{
    char *out = pOut->z;
    char *row = pC->aRow;

    /* Two pointer-typed members: unknown, not known-distinct. */
    return row < out;
}
