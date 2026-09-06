/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * `TCLSH_INIT_PROC` is an `extern` function prototype (pointer return type)
 * declared inline inside a function body, guarded by an `#if
 * defined(TCLSH_INIT_PROC)` whose macro isn't actually defined in this
 * translation unit -- aurora-lint has no preprocessor, so the guarded prototype and
 * its call site are both modeled as reachable. The prototype's declarator
 * shape (`pointer_declarator` wrapping a `function_declarator`) was
 * previously matched by the same code path as a plain pointer *variable*
 * declaration (`const char *p;`), tracking the function's own name as an
 * uninitialized local -- so the later call `zScript = TCLSH_INIT_PROC(interp);`
 * flagged the function name itself as "used uninitialized" (task 461
 * category 8; sqlite's tclsqlite.c TCLSH_MAIN).
 */
struct Tcl_Interp;
typedef struct Tcl_Interp Tcl_Interp;

int f(Tcl_Interp *interp) {
    const char *zScript = 0;
#if defined(TCLSH_INIT_PROC)
    extern const char *TCLSH_INIT_PROC(Tcl_Interp *);
#endif
#if defined(TCLSH_INIT_PROC)
    zScript = TCLSH_INIT_PROC(interp);
#endif
    if (zScript == 0) {
        return 1;
    }
    return 0;
}
