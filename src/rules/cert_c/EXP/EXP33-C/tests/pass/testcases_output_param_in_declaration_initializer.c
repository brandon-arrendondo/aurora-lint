/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `pStmt` is written
 * through its output argument by sqlite3_prepare_v2() (index 3, per
 * INITIALIZING_FUNCTIONS), and that call is the initializer of a
 * declaration statement (`int rc = sqlite3_prepare_v2(...)`) rather than a
 * plain assignment. The transfer function must process a declaration's
 * initializer expression for side effects, not just classify it, or the
 * output-parameter write on `pStmt` is invisible and its next read is
 * misflagged as uninitialized.
 */

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
int sqlite3_prepare_v2(sqlite3 *db, const char *sql, int n, sqlite3_stmt **ppStmt, const char **tail);
int sqlite3_step(sqlite3_stmt *s);

int foo(sqlite3 *db, const char *sql) {
    sqlite3_stmt *pStmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, 0);
    if (rc == 0) {
        sqlite3_step(pStmt);
    }
    return rc;
}
