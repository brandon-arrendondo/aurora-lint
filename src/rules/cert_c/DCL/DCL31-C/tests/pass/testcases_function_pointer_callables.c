/*
 * Rule: DCL31-C
 * Source: task 691 (sqlite ext/fts5/fts5_tokenize.c:165 callback style)
 * Status: PASS - Calling a function-pointer-typed parameter or local variable
 * is not a call to an undeclared function; the declarator fully declares it.
 * Regression: task 691 — 32 sqlite findings from this FP class.
 */

/* Function-pointer parameter, called directly by name */
static int via_param(int (*xToken)(int, int), void *pCtx) {
    (void)pCtx;
    return xToken(1, 2);
}

/* Function-pointer local variable, initialized then called */
static int via_local(int arg) {
    int (*xLocal)(int) = 0;
    return xLocal(arg);
}

/* Pointer-returning callback parameter, mirroring sqlite's xToken shape */
static int fts5AsciiTokenize(
    void *pCtx,
    int flags,
    const char *pFold,
    int nByte,
    int is,
    int ie,
    int (*xToken)(void *, int, const char *, int, int, int)
) {
    return xToken(pCtx, flags, pFold, nByte, is, ie);
}
