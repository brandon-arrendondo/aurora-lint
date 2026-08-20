/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 469 -- hostap db_table_exists FP class)
 * Status: PASS - Should NOT trigger STR02-C violation
 */

static int db_table_exists(sqlite3 *db, const char *name) {
    char cmd[128];
    sqlite3_stmt *stmt;
    int rc;
    snprintf(cmd, sizeof(cmd), "SELECT name FROM sqlite_master WHERE name='%s'", name);
    rc = sqlite3_exec(db, cmd, 0, 0, 0);
    return rc == SQLITE_OK;
}

void setup(sqlite3 *db) {
    if (!db_table_exists(db, "pseudonyms")) {
        db_table_exists(db, "reauth");
    }
}
