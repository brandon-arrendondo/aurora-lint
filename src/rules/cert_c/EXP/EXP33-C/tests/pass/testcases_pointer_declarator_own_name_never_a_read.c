/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 *
 * A pointer variable's own declared name -- whether bare (`VdbeOp *pCaller;`)
 * or with an initializer (`Mem *pMem = p->pResultRow;`) -- is never itself a
 * read; it is the point storage comes into existence. is_read_context only
 * special-cased bare scalar identifiers directly parented by "declaration"/
 * "init_declarator"; a pointer wraps the identifier in a "pointer_declarator"
 * layer first, which fell through to the read-context catch-all. That is
 * normally harmless (nothing is tracked yet at a fresh declaration), but
 * combined with sqc's dataflow having no block-scoping (a variable declared
 * inside a loop body can leak state across the loop's back edge into a
 * shared predecessor of every iteration), it produced real false positives
 * on straight-line "declare, assign unconditionally, use immediately"
 * pointer locals -- exactly this shape, matching sqlite's vdbe.c
 * (`VdbeOp *pCaller;` / `Mem *pMem = p->pResultRow;`) (task 391).
 */

typedef struct Mem Mem;
struct Mem { int flags; };
typedef struct Ctx Ctx;
struct Ctx { Mem *pResultRow; };

Mem *lookupMem(Ctx *ctx);

int useBare(Ctx *ctx) {
    Mem *pCaller;
    pCaller = lookupMem(ctx);
    return pCaller->flags;
}

int useWithInitializer(Ctx *ctx) {
    Mem *pMem = ctx->pResultRow;
    return pMem->flags;
}
