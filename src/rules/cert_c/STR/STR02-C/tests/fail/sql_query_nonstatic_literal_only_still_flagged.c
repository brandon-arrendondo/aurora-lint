/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 469 -- literal-only-param suppression must
 *   stay scoped to `static` functions; a non-static function could have
 *   external callers this file can't see, so it must stay conservative)
 * Status: FAIL - Should trigger STR02-C violation
 */

int db_table_exists(sqlite3 *db, const char *name) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "SELECT name FROM sqlite_master WHERE name='%s'", name);
    return sqlite3_exec(db, cmd, 0, 0, 0) == SQLITE_OK;
}

void setup(sqlite3 *db) {
    db_table_exists(db, "pseudonyms");
}
