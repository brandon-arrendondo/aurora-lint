/*
 * Rule: API00-C
 * Source: real-world (task 745)
 * Status: PASS - Should NOT trigger API00-C violation
 */

/*
 * Three ways a pointer parameter's own NULL guard went unseen. All three come
 * from task 664's API00-C POINTER adjudication sample, where the guard sits
 * inside the flagged function -- so this was a detection bug, not a scoping
 * question. The scan used to look at the body's top-level statement list only,
 * and decided guard polarity by matching the condition's TEXT.
 */

#include <stddef.h>

/*
 * 1. The guard sits behind a label, in a `goto failed` cleanup epilogue. A
 *    label wraps the statement it introduces, so the top-level scan walked
 *    past the labeled_statement without ever looking inside it.
 *    From sqlite src/vdbeapi.c sqlite3_set_auxdata().
 */
typedef struct AuxData {
    void *pAux;
    void (*xDeleteAux)(void *);
} AuxData;

AuxData *alloc_auxdata(void);

void set_auxdata(AuxData *pCtx, void *pAux, void (*xDelete)(void *))
{
    AuxData *pAuxData;

    if (pCtx == NULL)
        goto failed;
    pAuxData = alloc_auxdata();
    if (pAuxData == NULL)
        goto failed;
    pAuxData->pAux = pAux;
    pAuxData->xDeleteAux = xDelete;
    return;

failed:
    if (xDelete) {
        xDelete(pAux);
    }
}

/*
 * 2. `goto` is the early exit, not `return`. Control leaves the straight-line
 *    path either way, and in C error-handling style goto is the commoner
 *    spelling -- src/analyze/prescan.rs has always counted it.
 */
int consume(const char *buf, size_t len);

int read_record(const char *buf, size_t len)
{
    int rc = -1;

    if (!buf)
        goto done;
    rc = consume(buf, len);

done:
    return rc;
}

/*
 * 3. A truthiness guard written in sqlite's brace style. The parameter no
 *    longer sits immediately after the `(`, which is all the old text patterns
 *    ("(p)", "(p ", "(p &&") could match.
 *    From sqlite src/where.c sqlite3WhereBegin().
 */
typedef struct ExprList {
    int nExpr;
} ExprList;

int where_begin(ExprList *pOrderBy, int flags)
{
    if( pOrderBy && pOrderBy->nExpr >= 63 ){
        pOrderBy = 0;
    }
    if( pOrderBy ){
        flags |= pOrderBy->nExpr;
    }
    return flags;
}

/*
 * 4. Check-and-substitute: the parameter is tested against NULL and a fallback
 *    put in its place. Polarity does not matter to API00-C's question -- the
 *    function plainly validated the parameter -- and the then-branch here is
 *    the one where it IS null.
 *    From pure-ftpd src/quotas.c quota_update() and hostap
 *    src/wps/http_client.c http_client_url().
 */
int quota_update(int *overflow)
{
    int dummy_overflow;

    if (overflow == NULL) {
        overflow = &dummy_overflow;
    }
    *overflow = 0;
    return *overflow;
}
