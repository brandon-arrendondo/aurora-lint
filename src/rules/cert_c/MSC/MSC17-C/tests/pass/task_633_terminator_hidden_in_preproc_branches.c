/*
 * Rule: MSC17-C
 * Source: task_633
 * Status: PASS - Should NOT trigger MSC17-C violation
 */

/*
 * Rule: MSC17-C - Finish every set of statements associated with a case
 * label with a break statement
 * Status: PASS
 * Reason: sqlite src/os_unix.c:4271 / src/tclsqlite.c:3202 pattern -- a
 * braced case body's only content is a #if/#ifdef/#else block whose every
 * branch (both the #if side and a mandatory #else) ends in break/return,
 * so the case can never actually fall through no matter which branch the
 * preprocessor selects. The braces matter: a braced case body is a single
 * compound_statement item, and terminates_section's compound_statement
 * case finds the preproc_if via last_meaningful_child directly -- it
 * previously only recursed into compound_statement and if/else, never
 * preproc_if/preproc_ifdef/preproc_elif/preproc_else, so it fell to its
 * `_ => false` default and flagged every such case as a fallthrough.
 */

int handle(int op, int fd) {
    switch (op) {
    case 1: {
#if defined(FEATURE_A)
        return 1;
#else
        return 0;
#endif
    }
    case 2: {
#ifdef FEATURE_B
        break;
#else
        return -1;
#endif
    }
    default:
        break;
    }
    return fd;
}
